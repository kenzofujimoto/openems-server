//! Block log: hourly aggregates of blocked DNS answers, kept in memory until the next upload.
//! This is browsing data of whoever uses the machine: no user names, bounded, never written to disk.

use crate::policy::BlockReason;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, MutexGuard};

/// Rows kept between uploads; past this, new rows only increase `dropped`.
pub const MAX_ROWS: usize = 5000;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EventReason {
    Rule,
    Category(String),
    /// A public DNS over HTTPS service refused by anti-bypass.
    Doh,
    /// Explicit monitoring of DNS observations, without claiming a site category.
    Policy,
}

impl From<BlockReason> for EventReason {
    fn from(reason: BlockReason) -> Self {
        match reason {
            BlockReason::Rule => EventReason::Rule,
            BlockReason::Category(id) => EventReason::Category(id),
        }
    }
}

impl EventReason {
    fn name(&self) -> &'static str {
        match self {
            EventReason::Rule => "rule",
            EventReason::Category(_) => "category",
            EventReason::Doh => "doh",
            EventReason::Policy => "policy",
        }
    }

    fn category(&self) -> Option<String> {
        match self {
            EventReason::Category(id) => Some(id.clone()),
            _ => None,
        }
    }
}

/// One aggregate row; the field order is the upload order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    hour: i64,
    domain: String,
    reason: &'static str,
    category: Option<String>,
    action: &'static str,
}

#[derive(Default)]
struct State {
    rows: BTreeMap<Key, u64>,
    /// Last minute each (domain, reason) was counted: repeated queries in a minute count once.
    recent: HashMap<(String, &'static str, Option<String>, &'static str), i64>,
    dropped: u64,
    pending: Option<Batch>,
}

pub struct BlockLog {
    capacity: usize,
    state: Mutex<State>,
}

impl Default for BlockLog {
    fn default() -> Self {
        BlockLog::with_capacity(MAX_ROWS)
    }
}

/// Rows taken for one upload.
#[derive(Debug, Default, Clone)]
pub struct Batch {
    rows: Vec<(Key, u64)>,
    pub dropped: u64,
    batch_id: String,
}

impl Batch {
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty() && self.dropped == 0
    }

    /// Upload body without the client id: `{"events": [...], "dropped": n}`.
    pub fn to_json(&self) -> Value {
        let events: Vec<Value> = self
            .rows
            .iter()
            .map(|(key, count)| {
                let hour = jiff::Timestamp::from_second(key.hour).map(|hour| hour.to_string()).unwrap_or_default();
                let mut row = json!({"hour": hour, "domain": key.domain, "reason": key.reason, "count": count});
                if let Some(category) = &key.category {
                    row["category"] = json!(category);
                }
                if key.action == "monitored" {
                    row["action"] = json!("monitored");
                    row["source"] = json!("dns");
                }
                row
            })
            .collect();
        json!({"events": events, "dropped": self.dropped, "batch_id":self.batch_id})
    }
}

impl BlockLog {
    pub fn with_capacity(capacity: usize) -> Self {
        BlockLog { capacity, state: Mutex::new(State::default()) }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // Counters stay consistent under poison: every update is a single assignment.
        self.state.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    pub fn record(&self, domain: &str, reason: &EventReason) {
        self.record_at(domain, reason, jiff::Timestamp::now());
    }

    pub fn record_at(&self, domain: &str, reason: &EventReason, when: jiff::Timestamp) {
        self.record_action_at(domain, reason, "blocked", when);
    }

    pub fn monitor(&self, domain: &str, reason: &EventReason) {
        self.record_action_at(domain, reason, "monitored", jiff::Timestamp::now());
    }

    fn record_action_at(&self, domain: &str, reason: &EventReason, action: &'static str, when: jiff::Timestamp) {
        let second = when.as_second();
        let minute = second.div_euclid(60);
        let mut state = self.lock();
        let identity = (domain.to_owned(), reason.name(), reason.category(), action);
        if state.recent.get(&identity) == Some(&minute) {
            return;
        }
        if state.recent.len() >= self.capacity.saturating_mul(2) {
            state.recent.retain(|_, counted| *counted == minute);
        }
        // Under a flood of unique domains in one minute, retaining current entries alone
        // does not free space. Keep counting drops without allocating more identities.
        if state.recent.len() < self.capacity.saturating_mul(2) {
            state.recent.insert(identity, minute);
        }
        let key = Key {
            hour: second.div_euclid(3600) * 3600,
            domain: domain.to_owned(),
            reason: reason.name(),
            category: reason.category(),
            action,
        };
        let capacity = self.capacity;
        add(&mut state, key, 1, capacity);
    }

    /// Drain everything recorded so far.
    pub fn take(&self) -> Batch {
        let mut state = self.lock();
        let rows = std::mem::take(&mut state.rows).into_iter().collect();
        Batch { rows, dropped: std::mem::take(&mut state.dropped), batch_id: new_batch_id() }
    }

    /// Freeze a batch until acknowledged; retrying cannot merge later observations into it.
    pub fn begin_upload(&self) -> Batch {
        let mut state = self.lock();
        if let Some(batch) = &state.pending {
            return batch.clone();
        }
        let batch = Batch {
            rows: std::mem::take(&mut state.rows).into_iter().collect(),
            dropped: std::mem::take(&mut state.dropped),
            batch_id: new_batch_id(),
        };
        if !batch.is_empty() {
            state.pending = Some(batch.clone())
        }
        batch
    }

    pub fn finish_upload(&self, batch_id: &str) {
        let mut state = self.lock();
        if state.pending.as_ref().is_some_and(|batch| batch.batch_id == batch_id) {
            state.pending = None
        }
    }

    /// Put back a batch whose upload failed; rows that no longer fit become `dropped`.
    pub fn restore(&self, batch: Batch) {
        let mut state = self.lock();
        let capacity = self.capacity;
        for (key, count) in batch.rows {
            add(&mut state, key, count, capacity);
        }
        state.dropped = state.dropped.saturating_add(batch.dropped);
    }
}

fn add(state: &mut State, key: Key, count: u64, capacity: usize) {
    if let Some(existing) = state.rows.get_mut(&key) {
        *existing = existing.saturating_add(count);
    } else if state.rows.len() + state.pending.as_ref().map_or(0, |batch| batch.rows.len()) < capacity {
        state.rows.insert(key, count);
    } else {
        state.dropped = state.dropped.saturating_add(count);
    }
}

fn new_batch_id() -> String {
    // This is a deduplication identifier, not a credential or authorization token.
    format!("{:032x}{:032x}", fastrand::u128(..), fastrand::u128(..))
}

#[cfg(test)]
#[path = "events_bounds_tests.rs"]
mod bounds_tests;
