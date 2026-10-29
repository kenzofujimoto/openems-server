use openems_agent::controls::{Backend, ControlEvent, ControlManager, Inventory};
use openems_agent::error::{AgentError, Result};
use serde_json::{Value, json};
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Fake {
    calls: AtomicUsize,
    reject: bool,
}
impl Backend for Fake {
    fn apply(&self, _: &Value, _: &Path) -> openems_agent::controls::ApplyResult {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.reject {
            return Err(AgentError::Policy("enforcement unavailable".into()).into());
        }
        Ok(vec![event("one")])
    }
    fn inventory(&self, _: &Path) -> Result<Inventory> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(Inventory {
            collected_at: "2026-10-25T12:00:00Z".into(),
            applications: vec![json!({"name":"Example"})],
            usb_devices: vec![],
        })
    }
    fn capabilities(&self) -> Vec<String> {
        vec!["controls:test".into()]
    }
}
fn event(target: &str) -> ControlEvent {
    ControlEvent {
        at: "2026-10-25T12:00:00Z".into(),
        kind: "app_block".into(),
        target: target.into(),
        rule_id: "rule".into(),
    }
}

/// Inventory is collected in the background: poll the manager like the sync thread does.
fn collected(manager: &ControlManager, now: Instant) -> Result<Inventory> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(inventory) = manager.inventory_due(now)? {
            return Ok(inventory);
        }
        assert!(Instant::now() < deadline, "background inventory did not finish");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn inventory_is_opt_in_throttled_and_retained_until_uploaded() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(Fake::default());
    let manager = ControlManager::new(&dir.path().join("state.json"), backend.clone()).unwrap();
    let now = Instant::now();
    assert!(manager.inventory_due(now).unwrap().is_none());
    assert_eq!(backend.calls.load(Ordering::Relaxed), 0);
    manager.enable_inventory();
    let first = collected(&manager, now).unwrap();
    assert_eq!(manager.inventory_due(now + Duration::from_secs(10)).unwrap(), Some(first.clone()));
    assert_eq!(backend.calls.load(Ordering::Relaxed), 1);
    manager.inventory_uploaded(&first);
    assert!(manager.inventory_due(now + Duration::from_secs(299)).unwrap().is_none());
    assert!(collected(&manager, now + Duration::from_secs(300)).is_ok());
    assert_eq!(backend.calls.load(Ordering::Relaxed), 2);
}

/// Inventory whose collection waits for the test, like a slow Windows inventory adapter.
#[derive(Default)]
struct Gated {
    calls: AtomicUsize,
    released: std::sync::Mutex<usize>,
    signal: std::sync::Condvar,
    fail: bool,
}
impl Gated {
    fn release(&self) {
        *self.released.lock().unwrap() += 1;
        self.signal.notify_all();
    }
}
impl Backend for Gated {
    fn apply(&self, _: &Value, _: &Path) -> openems_agent::controls::ApplyResult {
        Ok(Vec::new())
    }
    fn inventory(&self, _: &Path) -> Result<Inventory> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let released = self.released.lock().unwrap();
        let _released = self.signal.wait_while(released, |released| *released < call).unwrap();
        if self.fail {
            return Err(AgentError::Local("inventory adapter failed".into()));
        }
        Ok(Inventory {
            collected_at: "2026-10-29T18:00:00Z".into(),
            applications: vec![json!({"name": format!("collection-{call}")})],
            usb_devices: vec![],
        })
    }
    fn capabilities(&self) -> Vec<String> {
        Vec::new()
    }
}

#[test]
fn a_slow_inventory_never_blocks_the_synchronization_caller() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(Gated::default());
    let manager = ControlManager::new(&dir.path().join("state.json"), backend.clone()).unwrap();
    manager.enable_inventory();
    let now = Instant::now();
    let started = Instant::now();
    assert!(manager.inventory_due(now).unwrap().is_none(), "collection must not run on the caller");
    assert!(manager.inventory_due(now).unwrap().is_none());
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(!manager.take_inventory_ready());
    backend.release();
    let inventory = collected(&manager, now).unwrap();
    assert_eq!(inventory.applications, vec![json!({"name":"collection-1"})]);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1, "only one collection may be in flight");
    assert!(manager.take_inventory_ready(), "a completed collection is announced once");
    assert!(!manager.take_inventory_ready());
}

#[test]
fn a_policy_change_during_collection_discards_the_stale_inventory() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(Gated::default());
    let manager = ControlManager::new(&dir.path().join("state.json"), backend.clone()).unwrap();
    manager.enable_inventory();
    let now = Instant::now();
    assert!(manager.inventory_due(now).unwrap().is_none());
    manager.apply(&json!({"usb_control":{"default_action":"block","rules":[]}}), false).unwrap();
    backend.release();
    backend.release();
    let inventory = collected(&manager, now).unwrap();
    assert_eq!(inventory.applications, vec![json!({"name":"collection-2"})], "state seen before the change is stale");
    assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn reapplying_an_unchanged_policy_keeps_the_inventory_but_a_release_refreshes_it() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(Gated::default());
    let manager = ControlManager::new(&dir.path().join("state.json"), backend.clone()).unwrap();
    manager.enable_inventory();
    let now = Instant::now();
    let block = json!({"usb_control":{"default_action":"block","rules":[]}});
    manager.apply(&block, false).unwrap();
    backend.release();
    let first = collected(&manager, now).unwrap();
    manager.inventory_uploaded(&first);
    manager.apply(&block, false).unwrap();
    assert!(manager.inventory_due(now).unwrap().is_none());
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1, "periodic reconciliation must not recollect");
    // Releasing a device emits no control event but changes what the inventory must report.
    manager.apply(&json!({"usb_control":{"default_action":"allow","rules":[]}}), false).unwrap();
    backend.release();
    assert_eq!(collected(&manager, now).unwrap().applications, vec![json!({"name":"collection-2"})]);
}

#[test]
fn a_failed_background_inventory_is_reported_once_and_throttled() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(Gated { fail: true, ..Default::default() });
    let manager = ControlManager::new(&dir.path().join("state.json"), backend.clone()).unwrap();
    manager.enable_inventory();
    let now = Instant::now();
    backend.release();
    assert!(manager.inventory_due(now).unwrap().is_none());
    let deadline = Instant::now() + Duration::from_secs(10);
    let error = loop {
        match manager.inventory_due(now) {
            Err(error) => break error,
            Ok(None) => assert!(Instant::now() < deadline, "failure was never reported"),
            Ok(Some(_)) => panic!("a failed collection produced an inventory"),
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(error.kind(), "LocalError");
    assert!(manager.inventory_due(now + Duration::from_secs(60)).unwrap().is_none());
    assert!(!manager.take_inventory_ready());
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn a_failed_control_never_becomes_a_success_event_and_dry_run_does_not_call_machine() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(Fake { reject: true, ..Default::default() });
    let manager = ControlManager::new(&dir.path().join("state.json"), backend.clone()).unwrap();
    assert!(manager.apply(&json!({}), true).unwrap().is_empty());
    assert_eq!(backend.calls.load(Ordering::Relaxed), 0);
    assert!(manager.apply(&json!({}), false).is_err());
    assert!(manager.pending().events.is_empty());
    assert_eq!(backend.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn offline_events_survive_restart_and_ack_only_removes_the_sent_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let backend = Arc::new(Fake::default());
    let first = ControlManager::new(&path, backend.clone()).unwrap();
    first.record(vec![event("one")]).unwrap();
    let batch = first.pending();
    first.record(vec![event("two")]).unwrap();
    first.acknowledge(&batch).unwrap();
    drop(first);
    let restored = ControlManager::new(&path, backend).unwrap();
    assert_eq!(restored.pending().events, vec![event("two")]);
    restored.acknowledge(&restored.pending()).unwrap();
    assert!(restored.pending().events.is_empty());
}

#[test]
fn event_queue_is_bounded_reports_drops_and_does_not_accept_unknown_kinds() {
    let dir = tempfile::tempdir().unwrap();
    let manager = ControlManager::new(&dir.path().join("state.json"), Arc::new(Fake::default())).unwrap();
    manager.record((0..300).map(|index| event(&index.to_string())).collect()).unwrap();
    let batch = manager.pending();
    assert_eq!(batch.events.len(), 256);
    assert_eq!(batch.dropped, 44);
    let invalid = ControlEvent { kind: "arbitrary".into(), ..event("bad") };
    assert!(manager.record(vec![invalid]).is_err());
    assert_eq!(manager.pending().events.len(), 256);
}

struct PartialEnforcement;

impl Backend for PartialEnforcement {
    fn apply(&self, _: &Value, _: &Path) -> openems_agent::controls::ApplyResult {
        Err(openems_agent::controls::ApplyFailure {
            error: AgentError::Policy("application control requires a restart".into()),
            events: vec![ControlEvent { kind: "usb_block".into(), ..event("external storage") }],
        })
    }

    fn inventory(&self, _: &Path) -> Result<Inventory> {
        unreachable!()
    }

    fn capabilities(&self) -> Vec<String> {
        Vec::new()
    }
}

#[test]
fn actions_completed_before_another_control_fails_remain_reportable_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state.json");
    let backend = Arc::new(PartialEnforcement);
    let manager = ControlManager::new(&state, backend.clone()).unwrap();

    assert!(manager.apply(&json!({}), false).is_err(), "the full policy must not be acknowledged");
    assert_eq!(manager.pending().events.len(), 1, "the real USB action must not be lost");
    drop(manager);

    let restarted = ControlManager::new(&state, backend).unwrap();
    assert_eq!(restarted.pending().events[0].kind, "usb_block");
    assert_eq!(restarted.pending().events[0].target, "external storage");
}
