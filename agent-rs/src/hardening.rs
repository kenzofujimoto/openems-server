//! Tamper protection decisions, independent of the Windows calls that carry them out.
//! Limit: a determined local administrator can always disable a user-mode agent; this stops
//! standard users and the common administrative paths, and restores and reports what changes.

use crate::error::Result;
use crate::tamper::{TamperKind, TamperLog};
use std::path::Path;

/// Service DACL: SYSTEM has full control; Administrators may query and start a stopped agent but
/// not stop, pause, reconfigure, delete or change permissions; authenticated users only query.
/// Windows Installer runs as SYSTEM, so install, upgrade and removal keep working.
pub const SERVICE_SDDL: &str = "D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPLORC;;;BA)(A;;CCLCSWLORC;;;AU)";

/// What the scheduled watchdog sees of the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceSnapshot {
    pub automatic: bool,
    pub running: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogAction {
    MakeAutomatic,
    Start,
}

/// `service` is None when the agent is not installed. Nothing is touched while Windows Installer
/// works, so installs, upgrades and removals are never undone.
pub fn watchdog_actions(service: Option<ServiceSnapshot>, installer_busy: bool) -> Vec<WatchdogAction> {
    let Some(service) = service else { return Vec::new() };
    if installer_busy {
        return Vec::new();
    }
    let mut actions = Vec::new();
    if !service.automatic {
        actions.push(WatchdogAction::MakeAutomatic);
    }
    if !service.running {
        actions.push(WatchdogAction::Start);
    }
    actions
}

type Probe = Box<dyn FnMut() -> Result<bool>>;
type Repair = Box<dyn FnMut() -> Result<()>>;

/// One protection: whether it is in place, and how to put it back.
pub struct Check {
    kind: TamperKind,
    present: Probe,
    repair: Repair,
    disabled: bool,
    failing: bool,
}

impl Check {
    pub fn new(
        kind: TamperKind,
        present: impl FnMut() -> Result<bool> + 'static,
        repair: impl FnMut() -> Result<()> + 'static,
    ) -> Self {
        Check { kind, present: Box::new(present), repair: Box::new(repair), disabled: false, failing: false }
    }
}

pub struct Watchdog {
    checks: Vec<Check>,
}

impl Watchdog {
    pub fn new(checks: Vec<Check>) -> Self {
        Watchdog { checks }
    }

    /// Repair what is missing and record it. Returns log lines; each problem is reported once.
    /// A repair that does not stick disables its check: wrong detection must not flap the system.
    pub fn run(&mut self, log: &TamperLog) -> Vec<String> {
        let mut notes = Vec::new();
        for check in self.checks.iter_mut().filter(|check| !check.disabled) {
            let present = (check.present)();
            match present {
                Ok(true) => check.failing = false,
                Ok(false) => {
                    let repaired = (check.repair)().and_then(|()| (check.present)());
                    match repaired {
                        Ok(true) => log.record(check.kind, check.kind.detail()),
                        Ok(false) => {
                            check.disabled = true;
                            notes.push(format!(
                                "watchdog stopped repairing {}: the repair did not stick",
                                check.kind.name()
                            ));
                        }
                        Err(error) if !check.failing => {
                            check.failing = true;
                            notes.push(format!("watchdog could not repair {} ({})", check.kind.name(), error.kind()));
                        }
                        Err(_) => {}
                    }
                }
                Err(error) if !check.failing => {
                    check.failing = true;
                    notes.push(format!("watchdog could not check {} ({})", check.kind.name(), error.kind()));
                }
                Err(_) => {}
            }
        }
        notes
    }
}

/// Mark this run as started; true when the previous run never reached a graceful stop.
pub fn begin_run(marker: &Path) -> Result<bool> {
    let previous = marker.try_exists()?;
    std::fs::write(marker, b"running\n")?;
    Ok(previous)
}

pub fn end_run(marker: &Path) -> Result<()> {
    match std::fs::remove_file(marker) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}
