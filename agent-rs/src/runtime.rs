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

#[derive(Debug, Clone, Default)]
pub struct Enforcement {
    pub sites: Vec<String>,
    pub killed: Vec<String>,
    /// The hosts file had to be rewritten.
    pub hosts_changed: bool,
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
    location: String,
    outcome: Outcome,
}

#[derive(Default)]
struct Inner {
    client_id: Option<String>,
    device_token: Option<String>,
    profile: Option<Assignment>,
    /// Full outside configuration including location definitions; never replaced by an inside profile.
    outside: Option<Assignment>,
    cached: Option<Assignment>,
    last_ack: Option<((String, i64, String), String)>,
    location: String,
    /// Live-only proof of freshness. A persisted client_ip never survives restart as a trusted signal.
    public_contact: Option<(Instant, std::net::IpAddr)>,
    next_sync: f64,
    failures: u32,
    pending: Option<Pending>,
    generation: u64,
    dns_state: Option<DnsCacheState>,
    /// Policy and open windows behind the last hosts write: a rewrite without a change here is tampering.
    hosts_state: Option<DnsCacheState>,
    /// Digest of each loaded category, to skip downloads that would not change anything.
    category_digests: std::collections::HashMap<String, String>,
    /// A new policy arrived: enforce (and persist it) now instead of at the next interval.
    enforce_requested: bool,
    /// The server has no uninstall codes (or refused for now): ask again only after this.
    uninstall_retry_at: f64,
}

pub struct Runtime {
    cfg: AgentConfig,
    api: ApiClient,
    inner: Mutex<Inner>,
    log: Logger,
    stop: Arc<StopSignal>,
    pub blocked_domains: Arc<crate::https_blockpage::BlockedDomains>,
    /// Logged once: the server has no block log route.
    block_log_unsupported: std::sync::atomic::AtomicBool,
    capabilities_sent: std::sync::atomic::AtomicBool,
    /// Protections found altered and restored, uploaded with each synchronization.
    pub tamper: Arc<crate::tamper::TamperLog>,
    tamper_unsupported: std::sync::atomic::AtomicBool,
    /// Status and notices for the component in each user session (session.json).
    pub session: crate::session::SessionBoard,
    controls: crate::controls::ControlManager,
    inventory_unsupported: std::sync::atomic::AtomicBool,
    control_events_unsupported: std::sync::atomic::AtomicBool,
}

/// Legacy block-only policies keep their historical best-effort behavior. Explicit actions
/// require complete data, including allow categories that suppress global observation.
fn category_data_ready(rules: &crate::policy::WebFilter, categories: &crate::categories::CategoryStore) -> bool {
    !rules.requires_category_data() || rules.referenced_categories().iter().all(|id| categories.has_data(id))
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
    let filter = assignment.web_filter()?;
    if filter.requires_monitoring() && !cfg.dns_filter {
        return Err(AgentError::Policy("web monitoring requires the DNS resolver".into()));
    }
    let rules = filter.rules_at(when);
    let sites = rules.blocked().to_vec();
    let release = assignment.unassigned && assignment.body.is_none();
    if cfg.dry_run {
        log(&format!("[dry-run] would apply {} domain block(s) and {} process rule(s)", sites.len(), apps.len()));
    }
    let hosts_changed = if cfg.dry_run {
        false
    } else if release || cfg.dns_filter {
        // In DNS mode the resolver enforces the rules; a hosts block would be a second source.
        clear_hosts(&cfg.hosts_path)?
    } else {
        apply_hosts(&rules, &cfg.hosts_path, if cfg.block_page { "127.0.0.1" } else { "0.0.0.0" })?
    };
    let killed = if apps.is_empty() { Vec::new() } else { processes_to_kill(&list_processes()?, &apps)? };
    for name in &killed {
        if !cfg.dry_run {
            kill_process(name)?;
        }
        log(&format!("{}{name}", if cfg.dry_run { "[dry-run] would terminate " } else { "terminated " }));
    }
    Ok(Enforcement { sites, killed, hosts_changed })
}

pub fn host_tags(cfg: &AgentConfig, assignment: &Assignment, enforcement: &Enforcement) -> Vec<String> {
    let mut tags = vec![
        format!("os:{}", platform_name()),
        if enforcement.killed.is_empty() { "app-control:clean".into() } else { "app-control:enforced".into() },
        format!("web-filter:{}-blocked", enforcement.sites.len()),
        // Understands safe_search and scheduled windows; the panel warns before publishing them otherwise.
        "web-filter:v2".into(),
        "web-filter:categories".into(),
        "web-filter:actions".into(),
    ];
    // Lets the panel warn before publishing wildcards to groups whose agents only use hosts.
    if cfg.dns_filter {
        tags.push("web-filter:dns".into());
        tags.push("web-filter:monitor".into());
        tags.push("web-filter:domain-rules:v1".into());
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
        let controls = crate::controls::ControlManager::new(&cfg.state_path, Arc::new(crate::controls::Machine))?;
        let mut inner = Inner { device_token: cfg.device_token.clone(), ..Default::default() };
        if let Some(state) = EndpointState::load(&cfg.state_path, &cfg.server, &cfg.devid)? {
            let profile =
                state.profile.as_ref().map(validate_assignment).transpose().map_err(|_| {
                    AgentError::State("cannot load endpoint state; preserve hosts and repair state".into())
                })?;
            inner.client_id = state.client_id;
            inner.device_token = state.device_token.or(inner.device_token);
            inner.cached = profile.clone();
            inner.outside = profile.clone();
            inner.profile = profile;
        }
        if inner.client_id.is_some() && cfg.invitation.is_some() && !cfg.dry_run {
            // Enrolled before invitations were removed after registration: drop the leftover copy.
            match cfg.forget_invitation() {
                Ok(true) => {
                    log("enrollment invitation removed from the configuration");
                    cfg.invitation = None;
                }
                Ok(false) => {}
                Err(error) => log(&format!("could not remove the used invitation ({})", error.summary())),
            }
        }
        let api = ApiClient::new(&cfg.server);
        let blocked_domains = Arc::new(crate::https_blockpage::BlockedDomains::default());
        if !cfg.dry_run
            && let Some(profile) = &inner.profile
        {
            // Offline start: categories downloaded earlier keep blocking before the server answers.
            let directory = crate::categories::cache_dir(&cfg.state_path);
            for id in Self::referenced_categories(profile) {
                match crate::categories::load_cached(&directory, &id, None) {
                    Some((digest, set)) => {
                        log(&format!("category {id} loaded from cache ({} domains)", set.len()));
                        blocked_domains.categories().insert(&id, set);
                        inner.category_digests.insert(id, digest);
                    }
                    None => log(&format!("category {id} has no cached copy yet; it does not block until downloaded")),
                }
            }
            let rules = profile.web_filter()?;
            if category_data_ready(&rules, blocked_domains.categories()) {
                blocked_domains.replace(rules);
            } else {
                log("cached action policy awaits required category data; monitoring remains inactive");
            }
        }
        Ok(Runtime {
            api,
            inner: Mutex::new(inner),
            log,
            stop,
            blocked_domains,
            block_log_unsupported: std::sync::atomic::AtomicBool::new(false),
            capabilities_sent: std::sync::atomic::AtomicBool::new(false),
            tamper: Arc::new(crate::tamper::TamperLog::default()),
            tamper_unsupported: std::sync::atomic::AtomicBool::new(false),
            session: crate::session::SessionBoard::open(&crate::session::path_for(&cfg.state_path)),
            controls,
            inventory_unsupported: std::sync::atomic::AtomicBool::new(false),
            control_events_unsupported: std::sync::atomic::AtomicBool::new(false),
            cfg,
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    /// The installed service reports inventories; diagnostic foreground runs only do so explicitly.
    pub fn enable_inventory(&self) {
        self.controls.enable_inventory();
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

    /// The board only informs users: a failed write is logged and retried with the next change.
    fn publish_session(&self) {
        if self.cfg.dry_run {
            return;
        }
        if let Err(error) = self.session.publish() {
            (self.log)(&format!("session notices not written ({})", error.kind()));
        }
    }

    fn stopping(&self) -> Result<()> {
        if self.stop.is_stopped() { Err(AgentError::Local("agent stopping".into())) } else { Ok(()) }
    }

    /// Keep this registration's uninstall secret (fetched, stored, then confirmed so the server stops
    /// handing it out) and mirror the server's removal release. Failures only delay removal protection.
    fn sync_uninstall(&self, client_id: &str, token: Option<&str>, release: Option<&str>, now: f64) {
        use crate::removal::{load, mark_acked, path_for, store_secret, update_release};
        let path = path_for(&self.cfg.state_path);
        let outcome = (|| -> Result<()> {
            // A damaged file is replaced when the server still hands the secret out.
            let stored = load(&path).unwrap_or(None).filter(|state| state.client_id == client_id);
            if !stored.as_ref().is_some_and(|state| state.acked) && now >= self.lock().uninstall_retry_at {
                let secret = match stored {
                    Some(state) => hex::decode(&state.secret).unwrap_or_default(),
                    None => match self.api.post("uninstall_secret", &json!({ "client_id": client_id }), token) {
                        Ok(answer) => {
                            let secret = answer
                                .get("secret")
                                .and_then(serde_json::Value::as_str)
                                .and_then(|secret| hex::decode(secret).ok())
                                .filter(|secret| secret.len() == 32)
                                .ok_or_else(|| AgentError::Transport("invalid uninstall secret".into()))?;
                            store_secret(&path, client_id, &secret)?;
                            secret
                        }
                        // Delivered before (a damaged or deleted file), or no master key on the server.
                        Err(AgentError::Status { code: 404 | 405 | 409 | 503, .. }) => {
                            self.lock().uninstall_retry_at = now + 3600.0;
                            return Ok(());
                        }
                        Err(error) => return Err(error),
                    },
                };
                let proof = crate::uninstall::delivery_proof(&secret);
                self.api.post("uninstall_secret/ack", &json!({ "client_id": client_id, "proof": proof }), token)?;
                mark_acked(&path)?;
                (self.log)("uninstall secret stored; removal now requires a code");
            }
            if update_release(&path, release)? {
                (self.log)(if release.is_some() {
                    "removal released by the server"
                } else {
                    "removal release revoked"
                });
            }
            Ok(())
        })();
        if let Err(error) = outcome {
            (self.log)(&format!("uninstall secret not synchronized ({}); retrying next cycle", error.summary()));
        }
    }

    /// Send the block log; a failed upload keeps its rows (within the limit) for the next cycle.
    fn upload_block_log(&self, client_id: &str, token: Option<&str>) {
        let log = self.blocked_domains.block_log();
        let batch = log.begin_upload();
        if batch.is_empty() {
            return;
        }
        let mut payload = batch.to_json();
        payload["client_id"] = json!(client_id);
        match self.api.post("events", &payload, token) {
            Ok(_) => {
                log.finish_upload(payload["batch_id"].as_str().unwrap_or_default());
            }
            // A server without the block log would refuse these rows forever.
            Err(AgentError::Status { code: 404 | 405, .. }) => {
                log.finish_upload(payload["batch_id"].as_str().unwrap_or_default());
                if !self.block_log_unsupported.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    (self.log)("server does not accept the block log; blocked answers are not reported");
                }
            }
            Err(error) => {
                (self.log)(&format!("block log upload failed ({}); kept for the next cycle", error.summary()));
            }
        }
    }

    /// Send tamper events; same retry and unsupported-server handling as the block log.
    fn upload_tamper(&self, client_id: &str, token: Option<&str>) {
        // The scheduled watchdog is another process: pick up what it wrote since the last cycle.
        let pending = self.cfg.state_path.with_file_name("tamper-pending.json");
        if let Err(error) = crate::tamper::drain_pending(&pending, &self.tamper) {
            (self.log)(&format!("watchdog events not read ({})", error.kind()));
        }
        let batch = self.tamper.take();
        if batch.is_empty() {
            return;
        }
        let mut payload = batch.to_json();
        payload["client_id"] = json!(client_id);
        match self.api.post("tamper", &payload, token) {
            Ok(_) => {}
            Err(AgentError::Status { code: 404 | 405, .. }) => {
                if !self.tamper_unsupported.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    (self.log)("server does not accept tamper events; they are only logged locally");
                }
            }
            Err(error) => {
                self.tamper.restore(batch);
                (self.log)(&format!("tamper event upload failed ({}); kept for the next cycle", error.summary()));
            }
        }
    }

    /// Upload bounded control reports independently of policy ACKs: failed uploads remain local.
    fn upload_controls(&self, client_id: &str, token: Option<&str>) {
        use std::sync::atomic::Ordering;
        if !self.control_events_unsupported.load(Ordering::Relaxed) {
            let batch = self.controls.pending();
            if !batch.events.is_empty() || batch.dropped > 0 {
                let payload =
                    json!({"client_id":client_id, "events":batch.events, "dropped":batch.dropped.min(1_000_000)});
                match self.api.post("control_events", &payload, token) {
                    Ok(_) => {
                        if let Err(error) = self.controls.acknowledge(&batch) {
                            (self.log)(&format!(
                                "control report acknowledgment not saved ({}); retrying",
                                error.kind()
                            ));
                        }
                    }
                    Err(AgentError::Status { code: 404 | 405, .. }) => {
                        self.control_events_unsupported.store(true, Ordering::Relaxed);
                        (self.log)("server does not support control events; reports remain in the bounded local queue");
                    }
                    Err(error) => {
                        (self.log)(&format!("control event upload failed ({}); kept locally", error.summary()))
                    }
                }
            }
        }
        if self.inventory_unsupported.load(Ordering::Relaxed) {
            return;
        }
        let inventory = match self.controls.inventory_due(Instant::now()) {
            Ok(Some(inventory)) => inventory,
            Ok(None) => return,
            Err(error) => {
                (self.log)(&format!("inventory collection failed ({}); retrying after its interval", error.kind()));
                return;
            }
        };
        let mut payload = match serde_json::to_value(&inventory) {
            Ok(payload) => payload,
            Err(_) => {
                (self.log)("inventory serialization failed");
                return;
            }
        };
        payload["client_id"] = json!(client_id);
        match self.api.post("inventory", &payload, token) {
            Ok(_) => self.controls.inventory_uploaded(&inventory),
            Err(AgentError::Status { code: 404 | 405, .. }) => {
                self.inventory_unsupported.store(true, Ordering::Relaxed);
                (self.log)("server does not support device inventory");
            }
            Err(error) => (self.log)(&format!("inventory upload failed ({}); retrying", error.summary())),
        }
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
                drop(inner);
                // The invitation is single-purpose: once the device holds its own token, keep no copy.
                match self.cfg.forget_invitation() {
                    Ok(true) => (self.log)("enrollment invitation removed from the configuration"),
                    Ok(false) => {}
                    Err(error) => (self.log)(&format!(
                        "could not remove the used invitation ({}); retrying at next start",
                        error.summary()
                    )),
                }
                client_id = Some(registration.client_id);
                token = Some(registration.device_token);
            }
            let id = client_id.clone().unwrap_or_default();
            self.api.post("messages/pull", &json!({ "client_id": id }), token.as_deref())?;
            self.api.post("refresh", &json!({ "client_id": id }), token.as_deref())?;
            if !self.capabilities_sent.load(std::sync::atomic::Ordering::Relaxed) {
                // The server can reject unsupported actions before delivering them. Advertise
                // capabilities first, retaining the outside group used by assignment rules.
                let group =
                    self.lock().outside.as_ref().map_or_else(|| self.cfg.vdom.clone(), |outside| outside.vdom.clone());
                let mut tags = vec![
                    format!("os:{}", platform_name()),
                    "web-filter:v2".into(),
                    "web-filter:categories".into(),
                    "web-filter:actions".into(),
                ];
                if self.cfg.dns_filter {
                    tags.extend([
                        "web-filter:dns".into(),
                        "web-filter:monitor".into(),
                        "web-filter:domain-rules:v1".into(),
                    ]);
                }
                if self.cfg.anti_bypass {
                    tags.push("web-filter:anti-bypass".into());
                }
                tags.extend(self.controls.capabilities());
                tags.push(format!("vdom:{group}"));
                self.api.post("host_tags", &json!({"client_id":id,"tags":tags}), token.as_deref())?;
                self.capabilities_sent.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            let assignment =
                validate_assignment(&self.api.get("config/assigned", &[("client_id", &id)], token.as_deref())?)?;
            self.stopping()?;
            Ok(assignment)
        })();
        let mut inner = self.lock();
        match attempt {
            Ok(assignment) => {
                let release =
                    assignment.raw.get("uninstall_release").and_then(serde_json::Value::as_str).map(str::to_owned);
                // Location metadata may change without changing the outside policy's identity.
                inner.enforce_requested = true;
                inner.public_contact = crate::locations::client_ip(&assignment.raw).map(|ip| (Instant::now(), ip));
                inner.outside = Some(assignment);
                inner.failures = 0;
                inner.next_sync = now + self.cfg.interval as f64;
                drop(inner);
                self.session.contact(jiff::Timestamp::now());
                self.publish_session();
                if !self.cfg.dry_run {
                    self.sync_categories(client_id.as_deref().unwrap_or_default(), token.as_deref());
                    self.upload_block_log(client_id.as_deref().unwrap_or_default(), token.as_deref());
                    self.upload_tamper(client_id.as_deref().unwrap_or_default(), token.as_deref());
                    self.upload_controls(client_id.as_deref().unwrap_or_default(), token.as_deref());
                    self.sync_uninstall(
                        client_id.as_deref().unwrap_or_default(),
                        token.as_deref(),
                        release.as_deref(),
                        now,
                    );
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
                    self.capabilities_sent.store(false, std::sync::atomic::Ordering::Relaxed);
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
        let referenced = self.lock().outside.as_ref().map(Self::referenced_categories).unwrap_or_default();
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

    fn referenced_categories(outside: &Assignment) -> Vec<String> {
        let mut categories = outside.web_filter().map(|rules| rules.referenced_categories()).unwrap_or_default();
        if let Ok(locations) = crate::locations::parse_locations(&outside.raw) {
            for location in locations {
                if let Ok(rules) = location.assignment.web_filter() {
                    categories.extend(rules.referenced_categories());
                }
            }
        }
        categories.sort();
        categories.dedup();
        categories
    }

    /// Apply the last valid policy; returns false only when enforcement failed.
    pub fn enforce_local(&self) -> bool {
        let locations = self
            .lock()
            .outside
            .as_ref()
            .and_then(|outside| crate::locations::parse_locations(&outside.raw).ok())
            .unwrap_or_default();
        let observed = if locations.is_empty() {
            crate::locations::Observed::default()
        } else {
            crate::network_signals::collect(&locations).unwrap_or_else(|error| {
                (self.log)(&format!("network signals unavailable ({}); treating location as outside", error.kind()));
                Default::default()
            })
        };
        self.enforce_observed(observed, Instant::now())
    }

    fn enforce_observed(&self, mut observed: crate::locations::Observed, at: Instant) -> bool {
        let (outside, public_contact) = {
            let inner = self.lock();
            (inner.outside.clone(), inner.public_contact)
        };
        let Some(outside) = outside else { return true };
        observed.public_ip = public_contact
            .filter(|(seen, _)| {
                at.saturating_duration_since(*seen) < Duration::from_secs(self.cfg.interval.saturating_mul(3))
            })
            .map(|(_, ip)| ip);
        let locations = crate::locations::parse_locations(&outside.raw).unwrap_or_default();
        let selected = crate::locations::choose(&locations, &observed);
        let location = selected.map_or_else(String::new, |location| location.id.clone());
        let assignment = selected.map_or_else(|| outside.clone(), |location| location.assignment.clone());
        let now = jiff::Timestamp::now();
        let result = assignment
            .web_filter()
            .and_then(|rules| {
                if rules.requires_monitoring() && !self.cfg.dns_filter {
                    return Err(AgentError::Policy("web monitoring requires the DNS resolver".into()));
                }
                if !category_data_ready(&rules, self.blocked_domains.categories()) {
                    return Err(AgentError::Policy("web action policy requires all referenced category data".into()));
                }
                let body = assignment.body.clone().map_or_else(|| json!({}), serde_json::Value::Object);
                let changed = self.controls.apply(&body, self.cfg.dry_run)?;
                for event in changed {
                    let text = match event.kind.as_str() {
                        "usb_block" => "Armazenamento USB bloqueado pela política da empresa.",
                        "usb_read_only" => "Armazenamento USB disponível somente para leitura.",
                        "app_network_policy" => "A política de acesso de aplicativos à rede foi aplicada.",
                        "app_control_applied" => "A política de execução de aplicativos foi aplicada.",
                        _ => "Uma ação de proteção de aplicativos foi registrada.",
                    };
                    self.session.notice(&event.kind, text.to_owned(), now);
                }
                if !self.cfg.dry_run {
                    self.blocked_domains.replace(rules);
                    let referenced = Self::referenced_categories(&outside);
                    self.blocked_domains.categories().retain(&referenced);
                    self.lock().category_digests.retain(|id, _| referenced.contains(id));
                }
                enforce_at(&self.cfg, &assignment, &self.log, now)
            })
            .and_then(|enforcement| {
                let mut inner = self.lock();
                let current = dns_cache_state(&assignment, now).ok();
                if enforcement.hosts_changed && current.is_some() && inner.hosts_state == current {
                    self.tamper.record(
                        crate::tamper::TamperKind::HostsRestored,
                        crate::tamper::TamperKind::HostsRestored.detail(),
                    );
                }
                inner.hosts_state = current;
                inner.cached = Some(outside);
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
                inner.profile = Some(assignment.clone());
                if inner.location != location {
                    let text = selected.map_or_else(
                        || "Fora da rede da empresa".to_owned(),
                        |location| format!("Rede da empresa ({}) detectada", location.name),
                    );
                    self.session.notice("network_location", text, now);
                    inner.location = location.clone();
                    (self.log)(&format!(
                        "network location changed: {}",
                        if location.is_empty() { "outside" } else { &location }
                    ));
                }
                self.session.set_protected(true);
                for name in &enforcement.killed {
                    self.session.app_closed(name, now);
                }
                inner.pending =
                    Some(Pending { generation, assignment, location, outcome: Outcome::Applied(enforcement) });
                drop(inner);
                self.publish_session();
                true
            }
            Err(error) => {
                inner.pending = Some(Pending {
                    generation,
                    assignment,
                    location,
                    outcome: Outcome::Failed(format!("enforcement failed: {}", error.kind())),
                });
                inner.last_ack = None;
                drop(inner);
                self.session.set_protected(false);
                self.publish_session();
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
        let acknowledgment = (identity.clone(), pending.location.clone());
        let attempt = (|| -> Result<()> {
            let applied = matches!(pending.outcome, Outcome::Applied(_));
            if !applied || last_ack.as_ref() != Some(&acknowledgment) {
                let mut payload = json!({
                    "client_id": client_id, "vdom": identity.0, "version": identity.1, "digest": identity.2, "success": applied,
                    "location": pending.location,
                });
                if let Outcome::Failed(error) = &pending.outcome {
                    payload["error"] = error.clone().into();
                }
                self.api.post("config/ack", &payload, token.as_deref())?;
                self.lock().last_ack = applied.then(|| acknowledgment.clone());
            }
            if let Outcome::Applied(enforcement) = &pending.outcome {
                let mut tags = host_tags(&self.cfg, &pending.assignment, enforcement);
                // Assignment rules may inspect tags: report the outside group to avoid feeding the
                // selected inside profile back into group selection and oscillating every cycle.
                if let Some(outside) = self.lock().outside.as_ref() {
                    tags.pop();
                    tags.push(format!("vdom:{}", outside.vdom));
                }
                let group = tags.pop();
                tags.extend(self.controls.capabilities());
                if let Some(group) = group {
                    tags.push(group);
                }
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
        let tags = host_tags(&config, &assignment, &Enforcement { sites: vec!["a.com".into()], ..Default::default() });
        assert_eq!(
            tags[1..],
            [
                "app-control:clean".to_owned(),
                "web-filter:1-blocked".into(),
                "web-filter:v2".into(),
                "web-filter:categories".into(),
                "web-filter:actions".into(),
                "vdom:Empty".into()
            ]
        );
    }

    fn network_runtime() -> (tempfile::TempDir, Runtime) {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = AgentConfig::new("http://127.0.0.1:9", "locations-test");
        cfg.allow_insecure_http = true;
        cfg.state_path = dir.path().join("state.json");
        cfg.hosts_path = dir.path().join("hosts");
        std::fs::write(&cfg.hosts_path, "127.0.0.1 localhost\n").unwrap();
        let make = |group: &str, blocked: Vec<&str>| {
            let body = json!({"web_filter": {"blocked": blocked}});
            json!({"vdom": group, "version": 1, "digest": crate::policy::policy_digest(body.as_object().unwrap()), "body": body})
        };
        let mut outside = make("Default", vec!["example.org"]);
        outside["client_ip"] = json!("200.1.2.3");
        outside["uninstall_release"] = json!("outside-release");
        outside["locations"] = json!([{
            "id": "office", "name": "Escritório", "cidrs": ["192.168.1.0/24"],
            "gateway_macs": ["00:11:22:33:44:55"], "dns_suffixes": [],
            "public_cidrs": ["200.1.2.0/24"], "probe": null,
            "assignment": make("Office", vec![])
        }]);
        EndpointState {
            server: cfg.server.clone(),
            devid: cfg.devid.clone(),
            client_id: Some("test".into()),
            profile: Some(outside),
            ..Default::default()
        }
        .save(&cfg.state_path)
        .unwrap();
        let runtime = Runtime::new(cfg, Arc::new(|_| {}), Arc::new(StopSignal::default())).unwrap();
        (dir, runtime)
    }

    fn office_observation() -> crate::locations::Observed {
        crate::locations::Observed {
            addresses: vec![("192.168.1.20".parse().unwrap(), 24)],
            gateway_macs: vec!["00:11:22:33:44:55".into()],
            ..Default::default()
        }
    }

    #[test]
    fn network_policy_is_reselected_offline_without_losing_outside_cache() {
        let (dir, runtime) = network_runtime();
        assert!(runtime.enforce_observed(office_observation(), Instant::now()));
        assert_eq!(runtime.lock().profile.as_ref().unwrap().vdom, "Office");
        assert!(!std::fs::read_to_string(dir.path().join("hosts")).unwrap().contains("example.org"));
        let persisted =
            EndpointState::load(&runtime.cfg.state_path, &runtime.cfg.server, &runtime.cfg.devid).unwrap().unwrap();
        let outside = persisted.profile.unwrap();
        assert_eq!(outside["vdom"], "Default");
        assert_eq!(outside["uninstall_release"], "outside-release");
        assert_eq!(outside["locations"][0]["id"], "office");
        let home = crate::locations::Observed { addresses: office_observation().addresses, ..Default::default() };
        assert!(runtime.enforce_observed(home, Instant::now()));
        assert_eq!(runtime.lock().profile.as_ref().unwrap().vdom, "Default");
        assert!(std::fs::read_to_string(dir.path().join("hosts")).unwrap().contains("example.org"));
        let board = crate::session::load(&crate::session::path_for(&runtime.cfg.state_path)).unwrap().unwrap();
        assert_eq!(board.notices.len(), 2);
        assert!(board.notices[0].text.contains("Rede da empresa"));
        assert!(board.notices[1].text.contains("Fora da rede da empresa"));
        assert_eq!(runtime.lock().pending.as_ref().unwrap().location, "");
    }

    #[test]
    fn public_address_expires_after_three_intervals_and_is_unknown_after_restart() {
        let (_dir, runtime) = network_runtime();
        let now = Instant::now();
        // The address in a persisted response has no live freshness proof.
        assert!(runtime.enforce_observed(Default::default(), now));
        assert_eq!(runtime.lock().profile.as_ref().unwrap().vdom, "Default");
        runtime.lock().public_contact = Some((now, "200.1.2.3".parse().unwrap()));
        assert!(runtime.enforce_observed(Default::default(), now + Duration::from_secs(44)));
        assert_eq!(runtime.lock().profile.as_ref().unwrap().vdom, "Office");
        assert_eq!(runtime.lock().pending.as_ref().unwrap().location, "office");
        assert!(runtime.enforce_observed(Default::default(), now + Duration::from_secs(45)));
        assert_eq!(runtime.lock().profile.as_ref().unwrap().vdom, "Default");
    }

    #[test]
    fn identical_network_observations_do_not_repeat_session_notices() {
        let (_dir, runtime) = network_runtime();
        for _ in 0..3 {
            assert!(runtime.enforce_observed(office_observation(), Instant::now()));
        }
        let board = crate::session::load(&crate::session::path_for(&runtime.cfg.state_path)).unwrap().unwrap();
        assert_eq!(board.notices.len(), 1);
    }

    struct UnavailableControls;
    impl crate::controls::Backend for UnavailableControls {
        fn apply(&self, _: &serde_json::Value, _: &std::path::Path) -> crate::controls::ApplyResult {
            Err(AgentError::Policy("control requires a reboot".into()).into())
        }
        fn inventory(&self, _: &std::path::Path) -> Result<crate::controls::Inventory> {
            unreachable!()
        }
        fn capabilities(&self) -> Vec<String> {
            Vec::new()
        }
    }

    #[test]
    fn unavailable_machine_controls_never_ack_success_or_replace_the_web_policy() {
        let (dir, mut runtime) = network_runtime();
        runtime.controls =
            crate::controls::ControlManager::new(&runtime.cfg.state_path, Arc::new(UnavailableControls)).unwrap();
        assert!(runtime.blocked_domains.contains("example.org"));
        assert!(!runtime.enforce_observed(office_observation(), Instant::now()));
        assert!(
            runtime.blocked_domains.contains("example.org"),
            "the failed inside policy must not release the previous DNS block"
        );
        assert!(matches!(runtime.lock().pending.as_ref().unwrap().outcome, Outcome::Failed(_)));
        assert!(!std::fs::read_to_string(dir.path().join("hosts")).unwrap().contains("example.org"));
        let board = crate::session::load(&crate::session::path_for(&runtime.cfg.state_path)).unwrap().unwrap();
        assert!(!board.protected);
    }
    include!("runtime_action_tests.rs");
}
