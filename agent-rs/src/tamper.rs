//! Tamper events: protections the agent found altered and restored, kept in memory until uploaded.
//! The scheduled watchdog runs as a separate process, so it leaves its events in a pending file.

use crate::error::{AgentError, Result};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

/// Events kept between uploads; past this, new events only increase `dropped`.
pub const MAX_EVENTS: usize = 200;
/// The same kind is reported at most once per window, so a fight with another tool cannot flood the panel.
const REPEAT_SECONDS: i64 = 600;
const MAX_PENDING: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TamperKind {
    DnsRuleRestored,
    WfpRestored,
    BrowserPolicyRestored,
    HostsRestored,
    ServiceConfigRestored,
    WatchdogRestored,
    ServiceStartedByWatchdog,
    UnexpectedExit,
}

impl TamperKind {
    pub const ALL: [TamperKind; 8] = [
        TamperKind::DnsRuleRestored,
        TamperKind::WfpRestored,
        TamperKind::BrowserPolicyRestored,
        TamperKind::HostsRestored,
        TamperKind::ServiceConfigRestored,
        TamperKind::WatchdogRestored,
        TamperKind::ServiceStartedByWatchdog,
        TamperKind::UnexpectedExit,
    ];

    /// Wire name; the server accepts only these.
    pub fn name(self) -> &'static str {
        match self {
            TamperKind::DnsRuleRestored => "dns_rule_restored",
            TamperKind::WfpRestored => "wfp_restored",
            TamperKind::BrowserPolicyRestored => "browser_policy_restored",
            TamperKind::HostsRestored => "hosts_restored",
            TamperKind::ServiceConfigRestored => "service_config_restored",
            TamperKind::WatchdogRestored => "watchdog_restored",
            TamperKind::ServiceStartedByWatchdog => "service_started_by_watchdog",
            TamperKind::UnexpectedExit => "unexpected_exit",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        TamperKind::ALL.into_iter().find(|kind| kind.name() == name)
    }

    /// Fixed description: details never carry user data.
    pub fn detail(self) -> &'static str {
        match self {
            TamperKind::DnsRuleRestored => "NRPT rule routing DNS to the agent was recreated",
            TamperKind::WfpRestored => "anti-bypass network filters were recreated",
            TamperKind::BrowserPolicyRestored => "browser DNS policies were reapplied",
            TamperKind::HostsRestored => "managed hosts block was rewritten",
            TamperKind::ServiceConfigRestored => "service start type, recovery or permissions were restored",
            TamperKind::WatchdogRestored => "watchdog scheduled task was recreated",
            TamperKind::ServiceStartedByWatchdog => "service was found stopped and started by the watchdog",
            TamperKind::UnexpectedExit => "previous run ended without a graceful stop",
        }
    }
}

#[derive(Debug, Clone)]
struct Event {
    at: jiff::Timestamp,
    kind: TamperKind,
    detail: String,
}

#[derive(Default)]
struct State {
    events: Vec<Event>,
    last: HashMap<TamperKind, i64>,
    dropped: u64,
}

pub struct TamperLog {
    capacity: usize,
    state: Mutex<State>,
}

impl Default for TamperLog {
    fn default() -> Self {
        TamperLog::with_capacity(MAX_EVENTS)
    }
}

#[derive(Debug, Default)]
pub struct Batch {
    events: Vec<Event>,
    pub dropped: u64,
}

impl Batch {
    pub fn is_empty(&self) -> bool {
        self.events.is_empty() && self.dropped == 0
    }

    /// Upload body without the client id: `{"events": [...], "dropped": n}`.
    pub fn to_json(&self) -> Value {
        let events: Vec<Value> = self
            .events
            .iter()
            .map(|event| json!({"at": event.at.to_string(), "kind": event.kind.name(), "detail": event.detail}))
            .collect();
        json!({"events": events, "dropped": self.dropped})
    }
}

impl TamperLog {
    pub fn with_capacity(capacity: usize) -> Self {
        TamperLog { capacity, state: Mutex::new(State::default()) }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // Each update is a single assignment, so a poisoned lock still holds consistent data.
        self.state.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    pub fn record(&self, kind: TamperKind, detail: &str) {
        self.record_at(kind, detail, jiff::Timestamp::now());
    }

    pub fn record_at(&self, kind: TamperKind, detail: &str, at: jiff::Timestamp) {
        let mut state = self.lock();
        let second = at.as_second();
        if state.last.get(&kind).is_some_and(|last| second - last < REPEAT_SECONDS) {
            return;
        }
        state.last.insert(kind, second);
        if state.events.len() < self.capacity {
            state.events.push(Event { at, kind, detail: detail.to_owned() });
        } else {
            state.dropped = state.dropped.saturating_add(1);
        }
    }

    pub fn take(&self) -> Batch {
        let mut state = self.lock();
        Batch { events: std::mem::take(&mut state.events), dropped: std::mem::take(&mut state.dropped) }
    }

    /// Put back a batch whose upload failed, ahead of newer events; what no longer fits is dropped.
    pub fn restore(&self, batch: Batch) {
        let mut state = self.lock();
        let newer = std::mem::take(&mut state.events);
        let mut merged = batch.events;
        merged.extend(newer);
        let overflow = merged.len().saturating_sub(self.capacity);
        merged.truncate(self.capacity);
        state.events = merged;
        state.dropped = state.dropped.saturating_add(batch.dropped).saturating_add(overflow as u64);
    }
}

/// Add an event to the pending file the service reads at start (used by the scheduled watchdog).
pub fn append_pending(path: &Path, kind: TamperKind, detail: &str, at: jiff::Timestamp) -> Result<()> {
    let mut events: Vec<Value> = std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Vec<Value>>(&bytes).ok())
        .unwrap_or_default();
    events.push(json!({"at": at.to_string(), "kind": kind.name(), "detail": detail}));
    let excess = events.len().saturating_sub(MAX_PENDING);
    events.drain(..excess);
    let data = serde_json::to_vec(&events).map_err(|error| AgentError::Local(format!("pending events: {error}")))?;
    crate::fsutil::atomic_write(path, &data, None, true)
}

/// Move pending events into `log` and delete the file; an unreadable file is discarded.
pub fn drain_pending(path: &Path, log: &TamperLog) -> Result<()> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for event in serde_json::from_slice::<Vec<Value>>(&bytes).unwrap_or_default() {
        let kind = event["kind"].as_str().and_then(TamperKind::from_name);
        let at = event["at"].as_str().and_then(|at| at.parse::<jiff::Timestamp>().ok());
        if let (Some(kind), Some(at)) = (kind, at) {
            log.record_at(kind, kind.detail(), at);
        }
    }
    std::fs::remove_file(path)?;
    Ok(())
}
