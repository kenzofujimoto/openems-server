use openems_agent::controls::{Backend, ControlEvent, ControlManager, Inventory};
use openems_agent::error::{AgentError, Result};
use serde_json::{Value, json};
use std::path::Path;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Fake { calls: AtomicUsize, reject: bool }
impl Backend for Fake {
    fn apply(&self, _: &Value, _: &Path) -> Result<Vec<ControlEvent>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.reject { return Err(AgentError::Policy("enforcement unavailable".into())); }
        Ok(vec![event("one")])
    }
    fn inventory(&self, _: &Path) -> Result<Inventory> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(Inventory { collected_at: "2026-10-25T12:00:00Z".into(), applications: vec![json!({"name":"Example"})], usb_devices: vec![] })
    }
    fn capabilities(&self) -> Vec<String> { vec!["controls:test".into()] }
}
fn event(target: &str) -> ControlEvent {
    ControlEvent { at: "2026-10-25T12:00:00Z".into(), kind: "app_block".into(), target: target.into(), rule_id: "rule".into() }
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
    let first = manager.inventory_due(now).unwrap().unwrap();
    assert_eq!(manager.inventory_due(now + Duration::from_secs(10)).unwrap(), Some(first.clone()));
    assert_eq!(backend.calls.load(Ordering::Relaxed), 1);
    manager.inventory_uploaded(&first);
    assert!(manager.inventory_due(now + Duration::from_secs(299)).unwrap().is_none());
    assert!(manager.inventory_due(now + Duration::from_secs(300)).unwrap().is_some());
    assert_eq!(backend.calls.load(Ordering::Relaxed), 2);
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
