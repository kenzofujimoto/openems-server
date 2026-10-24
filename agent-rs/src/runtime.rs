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
    dns_state: Option<DnsCacheState>,
    /// Digest of each loaded category, to skip downloads that would not change anything.
    category_digests: std::collections::HashMap<String, String>,
    /// A new policy arrived: enforce (and persist it) now instead of at the next interval.
    enforce_requested: bool,
}

pub struct Runtime {
    cfg: AgentConfig,
    api: ApiClient,
    inner: Mutex<Inner>,
    log: Logger,
    stop: Arc<StopSignal>,
    pub blocked_domains: Arc<crate::https_blockpage::BlockedDomains>,
}

/// What the Windows DNS cache depends on in DNS mode: the policy and which windows are open.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsCacheState {
    identity: (String, i64, String),
    windows: Vec<bool>,
}

pub fn dns_cache_state(assignment: &Assignment, when: jiff::Timestamp) -> Result<DnsCacheState> {
    Ok(DnsCacheState { identity: assignment.identity(), windows: assignment.web_filter()?.active_windows(when) })
}

/// Cached answers outlive a policy change or a window edge by their upstream TTL; flush then.
/// The first observation needs no flush: installing the NRPT rule already cleared the cache.
pub fn dns_cache_flush_needed(previous: Option<&DnsCacheState>, current: &DnsCacheState) -> bool {
    previous.is_some_and(|previous| previous != current)
}

pub fn enforce(cfg: &AgentConfig, assignment: &Assignment, log: &Logger) -> Result<Enforcement> {
    enforce_at(cfg, assignment, log, jiff::Timestamp::now())
}

/// Enforcement as of `when`: scheduled windows open at that instant are part of the hosts block.
pub fn enforce_at(
    cfg: &AgentConfig,
    assignment: &Assignment,
    log: &Logger,
    when: jiff::Timestamp,
) -> Result<Enforcement> {
    let (_, apps) = assignment.blocked_lists()?;
    let rules = assignment.web_filter()?.rules_at(when);
    let sites = rules.blocked().to_vec();
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

pub fn host_tags(cfg: &AgentConfig, assignment: &Assignment, enforcement: &Enforcement) -> Vec<String> {
    let mut tags = vec![
        format!("os:{}", platform_name()),
        if enforcement.killed.is_empty() { "app-control:clean".into() } else { "app-control:enforced".into() },
        format!("web-filter:{}-blocked", enforcement.sites.len()),
        // Understands safe_search and scheduled windows; the panel warns before publishing them otherwise.
        "web-filter:v2".into(),
        "web-filter:categories".into(),
    ];
    // Lets the panel warn before publishing wildcards to groups whose agents only use hosts.
    if cfg.dns_filter {
        tags.push("web-filter:dns".into());
    }
    if cfg.anti_bypass {
        tags.push("web-filter:anti-bypass".into());
    }
    tags.push(format!("vdom:{}", assignment.vdom));
    tags
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
            blocked_domains.replace(profile.web_filter()?);
            // Offline start: categories downloaded earlier keep blocking before the server answers.
            let directory = crate::categories::cache_dir(&cfg.state_path);
            for id in blocked_domains.referenced_categories() {
                match crate::categories::load_cached(&directory, &id, None) {
                    Some((digest, set)) => {
                        log(&format!("category {id} loaded from cache ({} domains)", set.len()));
                        blocked_domains.categories().insert(&id, set);
                        inner.category_digests.insert(id, digest);
                    }
                    None => log(&format!("category {id} has no cached copy yet; it does not block until downloaded")),
                }
            }
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
                    match assignment.web_filter() {
                        Ok(rules) => self.blocked_domains.replace(rules),
                        Err(_) => return false,
                    }
                }
                if inner.profile.as_ref().map(Assignment::identity) != Some(assignment.identity()) {
                    inner.enforce_requested = true;
                }
                inner.profile = Some(assignment);
                inner.failures = 0;
                inner.next_sync = now + self.cfg.interval as f64;
                drop(inner);
                if !self.cfg.dry_run {
                    self.sync_categories(client_id.as_deref().unwrap_or_default(), token.as_deref());
                }
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

    /// Download the categories the policy uses, verify them against the manifest and cache them.
    /// Failures are logged and retried next cycle; a category without data never blocks.
    fn sync_categories(&self, client_id: &str, token: Option<&str>) {
        use crate::categories::{
            CategorySet, MAX_FILE_SIZE, cache_dir, file_digest, load_cached, store_cached, valid_digest,
        };
        let referenced = self.blocked_domains.referenced_categories();
        self.blocked_domains.categories().retain(&referenced);
        self.lock().category_digests.retain(|id, _| referenced.contains(id));
        if referenced.is_empty() {
            return;
        }
        let manifest = match self.api.get("categories", &[("client_id", client_id)], token) {
            Ok(manifest) => manifest,
            Err(error) => {
                (self.log)(&format!("category manifest unavailable ({}); cached categories continue", error.summary()));
                return;
            }
        };
        let directory = cache_dir(&self.cfg.state_path);
        for id in &referenced {
            let entry = manifest["categories"]
                .as_array()
                .and_then(|entries| entries.iter().find(|entry| entry["id"].as_str() == Some(id.as_str())));
            let Some((digest, size)) =
                entry.and_then(|entry| Some((entry["digest"].as_str()?, entry["size"].as_u64()?)))
            else {
                (self.log)(&format!("category {id} is not published by the server; it does not block yet"));
                continue;
            };
            if !valid_digest(digest) || size > MAX_FILE_SIZE {
                (self.log)(&format!("category {id} has an invalid manifest entry"));
                continue;
            }
            if self.lock().category_digests.get(id).map(String::as_str) == Some(digest) {
                continue;
            }
            let fetched = (|| -> Result<CategorySet> {
                if let Some((_, set)) = load_cached(&directory, id, Some(digest)) {
                    return Ok(set);
                }
                let query = [("client_id", client_id), ("id", id.as_str()), ("digest", digest)];
                // ureq rejects a body that reaches its limit, so allow one byte more and check the size here.
                let bytes = self.api.get_bytes("categories/file", &query, token, size + 1)?;
                if bytes.len() as u64 != size || file_digest(&bytes) != digest {
                    return Err(AgentError::Policy("category file does not match its digest".into()));
                }
                let set = CategorySet::parse(&bytes)?;
                store_cached(&directory, id, digest, &bytes)?;
                Ok(set)
            })();
            match fetched {
                Ok(set) => {
                    let count = set.len();
                    self.blocked_domains.categories().insert(id, set);
                    self.lock().category_digests.insert(id.clone(), digest.to_owned());
                    (self.log)(&format!("category {id} loaded ({count} domains)"));
                }
                Err(error) => (self.log)(&format!("category {id} not updated ({})", error.summary())),
            }
        }
    }

    /// Apply the last valid policy; returns false only when enforcement failed.
    pub fn enforce_local(&self) -> bool {
        let Some(assignment) = self.lock().profile.clone() else { return true };
        let now = jiff::Timestamp::now();
        let result = enforce_at(&self.cfg, &assignment, &self.log, now).and_then(|enforcement| {
            let mut inner = self.lock();
            inner.cached = Some(assignment.clone());
            self.save(&inner)?;
            Ok(enforcement)
        });
        if result.is_ok() && self.cfg.dns_filter && !self.cfg.dry_run {
            self.flush_on_dns_change(&assignment, now);
        }
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

    fn flush_on_dns_change(&self, assignment: &Assignment, now: jiff::Timestamp) {
        let Ok(current) = dns_cache_state(assignment, now) else { return };
        let stale = {
            let mut inner = self.lock();
            let stale = dns_cache_flush_needed(inner.dns_state.as_ref(), &current);
            inner.dns_state = Some(current);
            stale
        };
        if stale && let Err(error) = crate::hosts::flush_dns() {
            (self.log)(&format!("DNS cache flush failed ({}); answers expire within their TTL", error.kind()));
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
                let tags = host_tags(&self.cfg, &pending.assignment, enforcement);
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
            // A new policy wakes the loop early, so a restart soon after it arrives cannot lose it.
            let deadline = Instant::now() + Duration::from_secs(self.cfg.interval);
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() || worker.is_finished() {
                    break;
                }
                if self.stop.wait(remaining.min(Duration::from_millis(250))) {
                    break;
                }
                if std::mem::take(&mut self.lock().enforce_requested) {
                    break;
                }
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
        let config = AgentConfig::new("https://ems.example.com", "PC1");
        let tags = host_tags(&config, &assignment, &Enforcement { sites: vec!["a.com".into()], killed: vec![] });
        assert_eq!(
            tags[1..],
            [
                "app-control:clean".to_owned(),
                "web-filter:1-blocked".into(),
                "web-filter:v2".into(),
                "web-filter:categories".into(),
                "vdom:Empty".into()
            ]
        );
    }
}
