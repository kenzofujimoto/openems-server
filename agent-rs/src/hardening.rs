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

/// Trustee -> set of two-letter rights for each allow ACE in the DACL part of `sddl`.
pub fn dacl_rights(sddl: &str) -> std::collections::BTreeMap<String, std::collections::BTreeSet<String>> {
    let dacl = sddl.split("S:").next().unwrap_or_default();
    let mut aces = std::collections::BTreeMap::new();
    for ace in dacl.split('(').filter_map(|ace| ace.strip_suffix(')')) {
        let fields: Vec<&str> = ace.split(';').collect();
        if fields.len() < 6 || fields[0] != "A" {
            continue;
        }
        let rights: std::collections::BTreeSet<String> =
            fields[2].as_bytes().chunks(2).map(|pair| String::from_utf8_lossy(pair).into_owned()).collect();
        aces.entry(fields[5].to_owned()).or_insert_with(std::collections::BTreeSet::new).extend(rights);
    }
    aces
}

/// Same allow ACEs and rights, whatever order Windows prints them in.
pub fn same_dacl(left: &str, right: &str) -> bool {
    dacl_rights(left) == dacl_rights(right)
}

fn escape_xml(text: &str) -> String {
    // Element text only: quotes need no escaping.
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Task Scheduler definition: SYSTEM runs `<exe> watchdog` at boot and every 5 minutes.
pub fn watchdog_task_xml(executable: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Starts the openems agent again if it was disabled or stopped.</Description></RegistrationInfo>
  <Triggers>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
    <TimeTrigger>
      <Repetition><Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
      <StartBoundary>2026-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author"><Exec><Command>{}</Command><Arguments>watchdog</Arguments></Exec></Actions>
</Task>
"#,
        escape_xml(&format!("\"{executable}\""))
    )
}
