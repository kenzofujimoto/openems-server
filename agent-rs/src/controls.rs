//! Native control orchestration and bounded offline reporting. An unavailable control is an error.

use crate::error::{AgentError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

const MAX_EVENTS: usize = 256;
const INVENTORY_INTERVAL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlEvent {
    pub at: String,
    pub kind: String,
    pub target: String,
    pub rule_id: String,
}

impl ControlEvent {
    fn valid(&self) -> bool {
        matches!(
            self.kind.as_str(),
            "usb_block"
                | "usb_read_only"
                | "app_block"
                | "app_network_block"
                | "app_control_applied"
                | "app_network_policy"
        ) && self.at.parse::<jiff::Timestamp>().is_ok()
            && !self.target.is_empty()
            && self.target.chars().count() <= 512
            && !self.target.chars().any(char::is_control)
            && !self.rule_id.is_empty()
            && self.rule_id.chars().count() <= 64
            && !self.rule_id.chars().any(char::is_control)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventBatch {
    pub events: Vec<ControlEvent>,
    pub dropped: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Inventory {
    pub collected_at: String,
    pub applications: Vec<Value>,
    pub usb_devices: Vec<Value>,
}

/// Actions already applied must remain reportable even if another requested control fails.
#[derive(Debug)]
pub struct ApplyFailure {
    pub error: AgentError,
    pub events: Vec<ControlEvent>,
}

impl From<AgentError> for ApplyFailure {
    fn from(error: AgentError) -> Self {
        Self { error, events: Vec::new() }
    }
}

pub type ApplyResult = std::result::Result<Vec<ControlEvent>, ApplyFailure>;

pub trait Backend: Send + Sync {
    fn apply(&self, body: &Value, state_path: &Path) -> ApplyResult;
    fn inventory(&self, state_path: &Path) -> Result<Inventory>;
    fn capabilities(&self) -> Vec<String>;
}

#[derive(Default)]
pub struct Machine;

#[cfg(windows)]
fn events(events: Vec<crate::windows_control::Event>) -> Vec<ControlEvent> {
    let at = jiff::Timestamp::now().to_string();
    events
        .into_iter()
        .map(|event| ControlEvent {
            at: at.clone(),
            kind: event.kind,
            target: event.detail.chars().filter(|character| !character.is_control()).take(512).collect(),
            rule_id: event.rule_id,
        })
        .collect()
}

impl Backend for Machine {
    fn apply(&self, body: &Value, state_path: &Path) -> ApplyResult {
        #[cfg(windows)]
        {
            let usb = crate::usb::validate(body.get("usb_control"))?;
            let apps = crate::applications::validate(body.get("app_control"))?;
            let mut changed = events(crate::usb::reconcile(&usb, state_path)?.events);
            let applications = match crate::applications::reconcile(&apps, state_path) {
                Ok(outcome) => outcome,
                Err(error) => return Err(ApplyFailure { error, events: changed }),
            };
            changed.extend(events(applications.events));
            Ok(changed)
        }
        #[cfg(target_os = "linux")]
        {
            crate::linux_support::apply_policy(body, state_path)?;
            Ok(Vec::new())
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            let _ = state_path;
            let usb = body.get("usb_control");
            let active_usb = usb.is_some_and(|usb| {
                usb.get("default_action").and_then(Value::as_str).is_some_and(|action| action != "allow")
                    || usb.get("rules").and_then(Value::as_array).is_some_and(|rules| !rules.is_empty())
            });
            let apps = body.get("app_control");
            let active_apps = ["execution_rules", "network_blocked"].iter().any(|key| {
                apps.and_then(|apps| apps.get(*key)).and_then(Value::as_array).is_some_and(|items| !items.is_empty())
            });
            if active_usb || active_apps {
                Err(AgentError::Policy("native controls are unavailable on this platform".into()).into())
            } else {
                Ok(Vec::new())
            }
        }
    }

    fn inventory(&self, state_path: &Path) -> Result<Inventory> {
        #[cfg(windows)]
        {
            let applications = crate::applications::inventory(state_path)?
                .into_iter()
                .map(serde_json::to_value)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| AgentError::Local("application inventory serialization failed".into()))?;
            let usb_devices = crate::usb::inventory(state_path)?
                .into_iter()
                .map(serde_json::to_value)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| AgentError::Local("USB inventory serialization failed".into()))?;
            Ok(Inventory { collected_at: jiff::Timestamp::now().to_string(), applications, usb_devices })
        }
        #[cfg(not(windows))]
        {
            let _ = state_path;
            Err(AgentError::Local("device inventory is not available on this platform".into()))
        }
    }

    fn capabilities(&self) -> Vec<String> {
        #[cfg(windows)]
        {
            let mut capabilities = crate::usb::capabilities();
            capabilities.extend(crate::applications::capabilities());
            capabilities.push("device-inventory:v1".into());
            capabilities
        }
        #[cfg(target_os = "linux")]
        {
            crate::linux_support::capability_tags()
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            Vec::new()
        }
    }
}

#[derive(Default)]
struct InventoryState {
    collected: Option<Instant>,
    pending: Option<Inventory>,
}

pub struct ControlManager {
    state_path: PathBuf,
    pending_path: PathBuf,
    backend: Arc<dyn Backend>,
    events: Mutex<EventBatch>,
    inventory: Mutex<InventoryState>,
    inventory_enabled: AtomicBool,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

impl ControlManager {
    pub fn new(state_path: &Path, backend: Arc<dyn Backend>) -> Result<Self> {
        let pending_path = state_path.with_file_name("control-pending.json");
        let pending = match std::fs::metadata(&pending_path) {
            Ok(metadata) => {
                if metadata.len() > 2 * 1024 * 1024 {
                    return Err(AgentError::State("control event queue is oversized".into()));
                }
                let batch: EventBatch = serde_json::from_slice(&std::fs::read(&pending_path)?)
                    .map_err(|_| AgentError::State("control event queue is invalid".into()))?;
                if batch.events.len() > MAX_EVENTS || !batch.events.iter().all(ControlEvent::valid) {
                    return Err(AgentError::State("control event queue is invalid".into()));
                }
                batch
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => EventBatch::default(),
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            state_path: state_path.to_owned(),
            pending_path,
            backend,
            events: Mutex::new(pending),
            inventory: Mutex::new(InventoryState::default()),
            inventory_enabled: AtomicBool::new(false),
        })
    }

    pub fn apply(&self, body: &Value, dry_run: bool) -> Result<Vec<ControlEvent>> {
        if dry_run {
            return Ok(Vec::new());
        }
        let changed = match self.backend.apply(body, &self.state_path) {
            Ok(changed) => changed,
            Err(failure) => {
                self.record(failure.events)?;
                return Err(failure.error);
            }
        };
        self.record(changed.clone())?;
        Ok(changed)
    }

    pub fn capabilities(&self) -> Vec<String> {
        self.backend.capabilities()
    }

    pub fn record(&self, changed: Vec<ControlEvent>) -> Result<()> {
        if changed.is_empty() {
            return Ok(());
        }
        if !changed.iter().all(ControlEvent::valid) {
            return Err(AgentError::Local("invalid native control event".into()));
        }
        let mut pending = lock(&self.events);
        for event in changed {
            if pending.events.contains(&event) {
                continue;
            }
            if pending.events.len() == MAX_EVENTS {
                pending.events.remove(0);
                pending.dropped = pending.dropped.saturating_add(1).min(1_000_000);
            }
            pending.events.push(event);
        }
        self.save_events(&pending)?;
        // A newly observed enforcement may also have changed the live device inventory.
        *lock(&self.inventory) = InventoryState::default();
        Ok(())
    }

    fn save_events(&self, pending: &EventBatch) -> Result<()> {
        let bytes =
            serde_json::to_vec(pending).map_err(|_| AgentError::Local("cannot encode control events".into()))?;
        crate::fsutil::atomic_write(&self.pending_path, &bytes, None, true)
    }

    pub fn pending(&self) -> EventBatch {
        lock(&self.events).clone()
    }

    pub fn acknowledge(&self, sent: &EventBatch) -> Result<()> {
        let mut pending = lock(&self.events);
        if !pending.events.starts_with(&sent.events) {
            return Ok(());
        }
        pending.events.drain(..sent.events.len());
        pending.dropped = pending.dropped.saturating_sub(sent.dropped);
        self.save_events(&pending)
    }

    pub fn enable_inventory(&self) {
        self.inventory_enabled.store(true, Ordering::Release);
    }

    pub fn inventory_due(&self, now: Instant) -> Result<Option<Inventory>> {
        if !self.inventory_enabled.load(Ordering::Acquire) {
            return Ok(None);
        }
        let mut state = lock(&self.inventory);
        if let Some(pending) = state.pending.as_ref() {
            return Ok(Some(pending.clone()));
        }
        if state.collected.is_some_and(|at| now.saturating_duration_since(at) < INVENTORY_INTERVAL) {
            return Ok(None);
        }
        // Also throttle collection failures; a missing native dependency must not spawn every second.
        state.collected = Some(now);
        let inventory = self.backend.inventory(&self.state_path)?;
        if inventory.applications.len() > 2000
            || inventory.usb_devices.len() > 512
            || inventory.collected_at.parse::<jiff::Timestamp>().is_err()
        {
            return Err(AgentError::Local("native inventory is invalid or oversized".into()));
        }
        state.pending = Some(inventory.clone());
        Ok(Some(inventory))
    }

    pub fn inventory_uploaded(&self, sent: &Inventory) {
        let mut state = lock(&self.inventory);
        if state.pending.as_ref() == Some(sent) {
            state.pending = None;
        }
    }
}

/// Pure planning: never executes scripts or applies a Windows/Linux policy.
pub fn plan(policy: &Value, inventory: Option<&Value>) -> Result<Value> {
    let policy = crate::policy::validate_policy(policy)?;
    let usb = crate::usb::validate(policy.get("usb_control"))?;
    let applications = crate::applications::validate(policy.get("app_control"))?;
    let mut decisions = Vec::new();
    let mut execution = applications.execution_rules.clone();
    if let Some(inventory) = inventory {
        let devices: Vec<crate::usb::Device> =
            serde_json::from_value(inventory.get("usb_devices").cloned().unwrap_or(json!([])))
                .map_err(|_| AgentError::Policy("invalid planning USB inventory".into()))?;
        if devices.len() > 512 {
            return Err(AgentError::Policy("planning inventory is oversized".into()));
        }
        for device in devices {
            decisions.push(json!({"instance_id":device.instance_id, "action":crate::usb::decide(&usb, &device)}));
        }
        if !execution.is_empty() {
            let apps: Vec<crate::applications::Application> =
                serde_json::from_value(inventory.get("applications").cloned().unwrap_or(json!([])))
                    .map_err(|_| AgentError::Policy("invalid planning application inventory".into()))?;
            if apps.len() > 2000 {
                return Err(AgentError::Policy("planning inventory is oversized".into()));
            }
            execution = crate::applications::resolve_rules(&applications, &apps)?;
        }
    }
    Ok(
        json!({"policy":policy, "usb_decisions":decisions, "execution_rules":execution, "network_blocked":applications.network_blocked}),
    )
}

pub fn cleanup(state: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        crate::applications::cleanup(state)?;
        crate::usb::cleanup(state)?;
    }
    #[cfg(target_os = "linux")]
    {
        crate::linux_support::remove_policy(state)?;
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = state;
    }
    Ok(())
}
