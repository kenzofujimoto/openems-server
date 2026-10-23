//! Enforcement loop: synchronization retries never disable the cached policy.

use crate::api::{ApiClient, platform_name};
use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use crate::hosts::{apply_hosts, clear_hosts};
use crate::policy::{Assignment, validate_assignment};
use crate::processes::{kill_process, list_processes, processes_to_kill};
use crate::state::EndpointState;
use serde_json::json;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub type Logger = Arc<dyn Fn(&str) + Send + Sync>;

/// Cooperative shutdown shared by the service handler and worker threads.
#[derive(Default)]
pub struct StopSignal {
    stopped: Mutex<bool>,
    wake: Condvar,
}

impl StopSignal {
    pub fn stop(&self) {
        *self.stopped.lock().unwrap_or_else(|poison| poison.into_inner()) = true;
        self.wake.notify_all();
    }

    pub fn is_stopped(&self) -> bool {
        *self.stopped.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    /// Sleep up to `duration`; returns true when stopping.
    pub fn wait(&self, duration: Duration) -> bool {
        let guard = self.stopped.lock().unwrap_or_else(|poison| poison.into_inner());
        let (guard, _) = self
            .wake
            .wait_timeout_while(guard, duration, |stopped| !*stopped)
            .unwrap_or_else(|poison| poison.into_inner());
        *guard
    }
}

#[derive(Debug, Clone)]
pub struct Enforcement {
    pub sites: Vec<String>,
    pub killed: Vec<String>,
}

#[derive(Debug, Clone)]
enum Outcome {
    Applied(Enforcement),
    Failed(String),
}

#[derive(Debug, Clone)]
struct Pending {
    generation: u64,
    assignment: Assignment,
    outcome: Outcome,
}

#[derive(Default)]
struct Inner {
    client_id: Option<String>,
    device_token: Option<String>,
    profile: Option<Assignment>,
    cached: Option<Assignment>,
    last_ack: Option<(String, i64, String)>,
    next_sync: f64,
    failures: u32,
    pending: Option<Pending>,
    generation: u64,
}

pub struct Runtime {
    cfg: AgentConfig,
    api: ApiClient,
    inner: Mutex<Inner>,
    log: Logger,
    stop: Arc<StopSignal>,
    pub blocked_domains: Arc<crate::https_blockpage::BlockedDomains>,
}

pub fn enforce(cfg: &AgentConfig, assignment: &Assignment, log: &Logger) -> Result<Enforcement> {
    let (sites, apps) = assignment.blocked_lists()?;
    let rules = assignment.web_rules()?;
    let release = assignment.unassigned && assignment.body.is_none();
    if cfg.dry_run {
        log(&format!("[dry-run] would apply {} domain block(s) and {} process rule(s)", sites.len(), apps.len()));
    } else if release || cfg.dns_filter {
        // In DNS mode the resolver enforces the rules; a hosts block would be a second source.
        clear_hosts(&cfg.hosts_path)?;
    } else {
        apply_hosts(&rules, &cfg.hosts_path, if cfg.block_page { "127.0.0.1" } else { "0.0.0.0" })?;
    }
    let killed = if apps.is_empty() { Vec::new() } else { processes_to_kill(&list_processes()?, &apps)? };
    for name in &killed {
        if !cfg.dry_run {
            kill_process(name)?;
        }
        log(&format!("{}{name}", if cfg.dry_run { "[dry-run] would terminate " } else { "terminated " }));
    }
    Ok(Enforcement { sites, killed })
}

pub fn host_tags(assignment: &Assignment, enforcement: &Enforcement) -> Vec<String> {
    vec![
        format!("os:{}", platform_name()),
        if enforcement.killed.is_empty() { "app-control:clean".into() } else { "app-control:enforced".into() },
        format!("web-filter:{}-blocked", enforcement.sites.len()),
        format!("vdom:{}", assignment.vdom),
    ]
}

impl Runtime {
    pub fn new(mut cfg: AgentConfig, log: Logger, stop: Arc<StopSignal>) -> Result<Self> {
        cfg.validate()?;
        let mut inner = Inner { device_token: cfg.device_token.clone(), ..Default::default() };
        if let Some(state) = EndpointState::load(&cfg.state_path, &cfg.server, &cfg.devid)? {
            let profile =
                state.profile.as_ref().map(validate_assignment).transpose().map_err(|_| {
                    AgentError::State("cannot load endpoint state; preserve hosts and repair state".into())
                })?;
            inner.client_id = state.client_id;
            inner.device_token = state.device_token.or(inner.device_token);
            inner.cached = profile.clone();
            inner.profile = profile;
        }
        let api = ApiClient::new(&cfg.server);
        let blocked_domains = Arc::new(crate::https_blockpage::BlockedDomains::default());
        if !cfg.dry_run
            && let Some(profile) = &inner.profile
        {
            blocked_domains.replace(profile.web_rules()?);
        }
        Ok(Runtime { cfg, api, inner: Mutex::new(inner), log, stop, blocked_domains })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    pub fn client_id(&self) -> Option<String> {
        self.lock().client_id.clone()
    }

    fn save(&self, inner: &Inner) -> Result<()> {
        if self.cfg.dry_run {
            return Ok(());
        }
        EndpointState {
            server: self.cfg.server.clone(),
            devid: self.cfg.devid.clone(),
            client_id: inner.client_id.clone(),
            device_token: inner.device_token.clone(),
            profile: inner.cached.as_ref().map(|assignment| assignment.raw.clone()),
        }
        .save(&self.cfg.state_path)
    }

    fn stopping(&self) -> Result<()> {
        if self.stop.is_stopped() { Err(AgentError::Local("agent stopping".into())) } else { Ok(()) }
    }

    /// Register if needed, drain notifications and fetch the assigned policy.
    pub fn synchronize(&self, now: f64) -> bool {
        let (mut client_id, mut token) = {
            let inner = self.lock();
            if now < inner.next_sync {
                return false;
            }
            (inner.client_id.clone(), inner.device_token.clone())
        };
        let attempt = (|| -> Result<Assignment> {
            if client_id.is_none() {
                let registration = self.api.register(
                    &self.cfg.devid,
                    &self.cfg.vdom,
                    self.cfg.invitation.as_deref(),
                    token.as_deref(),
                )?;
                self.stopping()?;
                let mut inner = self.lock();
                inner.client_id = Some(registration.client_id.clone());
                inner.device_token = Some(registration.device_token.clone());
                inner.last_ack = None;
                self.save(&inner)?;
                client_id = Some(registration.client_id);
                token = Some(registration.device_token);
            }
            let id = client_id.clone().unwrap_or_default();
            self.api.post("messages/pull", &json!({ "client_id": id }), token.as_deref())?;
            self.api.post("refresh", &json!({ "client_id": id }), token.as_deref())?;
            let assignment =
                validate_assignment(&self.api.get("config/assigned", &[("client_id", &id)], token.as_deref())?)?;
            self.stopping()?;
            Ok(assignment)
        })();
        let mut inner = self.lock();
        match attempt {
            Ok(assignment) => {
                // Revocation follows the newest validated policy immediately, not the next enforcement tick.
                if !self.cfg.dry_run {
                    match assignment.web_rules() {
                        Ok(rules) => self.blocked_domains.replace(rules),
                        Err(_) => return false,
                    }
                }
                inner.profile = Some(assignment);
                inner.failures = 0;
                inner.next_sync = now + self.cfg.interval as f64;
                true
            }
            Err(error) => {
                inner.failures += 1;
                let backoff = (self.cfg.interval as f64 * 2f64.powi(inner.failures.min(8) as i32)).min(300.0);
                inner.next_sync = now + backoff * (0.8 + fastrand::f64() * 0.4);
                // The server no longer recognises this identity (for example, its database was
                // recreated): enroll again, presenting the old credential as proof of possession.
                if matches!(error, AgentError::Status { code: 401 | 404, .. }) {
                    inner.client_id = None;
                }
                drop(inner);
                (self.log)(&format!("synchronization failed ({}); cached enforcement continues", error.summary()));
                false
            }
        }
    }

    /// Apply the last valid policy; returns false only when enforcement failed.
    pub fn enforce_local(&self) -> bool {
        let Some(assignment) = self.lock().profile.clone() else { return true };
        let result = enforce(&self.cfg, &assignment, &self.log).and_then(|enforcement| {
            let mut inner = self.lock();
            inner.cached = Some(assignment.clone());
            self.save(&inner)?;
            Ok(enforcement)
        });
        let mut inner = self.lock();
        inner.generation += 1;
        let generation = inner.generation;
        match result {
            Ok(enforcement) => {
                inner.pending = Some(Pending { generation, assignment, outcome: Outcome::Applied(enforcement) });
                true
            }
            Err(error) => {
                inner.pending = Some(Pending {
                    generation,
                    assignment,
                    outcome: Outcome::Failed(format!("enforcement failed: {}", error.kind())),
                });
                inner.last_ack = None;
                drop(inner);
                (self.log)(&format!("policy enforcement failed ({})", error.kind()));
                false
            }
        }
    }

    /// Acknowledge only what was really applied, then report host tags.
    pub fn report_pending(&self) {
        if self.cfg.dry_run {
            return;
        }
        let (pending, client_id, token, last_ack) = {
            let inner = self.lock();
            (inner.pending.clone(), inner.client_id.clone(), inner.device_token.clone(), inner.last_ack.clone())
        };
        let (Some(pending), Some(client_id)) = (pending, client_id) else { return };
        let identity = pending.assignment.identity();
        let attempt = (|| -> Result<()> {
            let applied = matches!(pending.outcome, Outcome::Applied(_));
            if !applied || last_ack.as_ref() != Some(&identity) {
                let mut payload = json!({
                    "client_id": client_id, "vdom": identity.0, "version": identity.1, "digest": identity.2, "success": applied,
                });
                if let Outcome::Failed(error) = &pending.outcome {
                    payload["error"] = error.clone().into();
                }
                self.api.post("config/ack", &payload, token.as_deref())?;
                self.lock().last_ack = applied.then(|| identity.clone());
            }
            if let Outcome::Applied(enforcement) = &pending.outcome {
                let tags = host_tags(&pending.assignment, enforcement);
                self.api.post("host_tags", &json!({ "client_id": client_id, "tags": tags }), token.as_deref())?;
            }
            Ok(())
        })();
        match attempt {
            Ok(()) => {
                let mut inner = self.lock();
                if inner.pending.as_ref().is_some_and(|current| current.generation == pending.generation) {
                    inner.pending = None;
                }
            }
            Err(error) => {
                (self.log)(&format!("policy status report failed ({}); retry next synchronization", error.kind()))
            }
        }
    }

    /// One synchronous cycle for diagnostics and `run-once`.
    pub fn cycle(&self, now: f64) -> bool {
        let connected = self.synchronize(now);
        let enforced = self.enforce_local();
        if connected {
            self.report_pending();
        }
        enforced
    }

    /// Long-running loop: enforcement every interval, synchronization on its own thread.
    pub fn run(self: Arc<Self>) -> Result<()> {
        let started = Instant::now();
        let worker = {
            let runtime = Arc::clone(&self);
            std::thread::Builder::new().name("openems-sync".into()).spawn(move || {
                while !runtime.stop.is_stopped() {
                    if runtime.synchronize(started.elapsed().as_secs_f64()) {
                        runtime.report_pending();
                    }
                    runtime.stop.wait(Duration::from_secs(1));
                }
            })?
        };
        while !self.stop.is_stopped() {
            self.enforce_local();
            if self.stop.wait(Duration::from_secs(self.cfg.interval)) {
                break;
            }
            if worker.is_finished() {
                break;
            }
        }
        self.stop.stop();
        worker.join().map_err(|_| AgentError::Local("endpoint synchronization worker terminated".into()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_signal_wakes_waiters() {
        let signal = Arc::new(StopSignal::default());
        let waiter = {
            let signal = Arc::clone(&signal);
            std::thread::spawn(move || signal.wait(Duration::from_secs(30)))
        };
        signal.stop();
        assert!(waiter.join().unwrap());
        assert!(signal.is_stopped());
    }

    #[test]
    fn tags_report_the_assigned_group_last() {
        let assignment = validate_assignment(
            &json!({"vdom": "Empty", "version": 0, "digest": "", "body": null, "unassigned": true}),
        )
        .unwrap();
        let tags = host_tags(&assignment, &Enforcement { sites: vec!["a.com".into()], killed: vec![] });
        assert_eq!(tags[1..], ["app-control:clean".to_owned(), "web-filter:1-blocked".into(), "vdom:Empty".into()]);
    }
}
