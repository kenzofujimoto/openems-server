//! Tamper protection (phase 5a): service permissions, watchdog decisions, repairs and tamper events.

use openems_agent::hardening::{
    Check, SERVICE_SDDL, ServiceSnapshot, Watchdog, WatchdogAction, begin_run, end_run, watchdog_actions,
};
use openems_agent::tamper::{TamperKind, TamperLog};
use serde_json::json;
use std::cell::Cell;
use std::rc::Rc;

/// Rights string of the ACE for `trustee` in a D:P(...)(...) SDDL.
fn rights(trustee: &str) -> String {
    SERVICE_SDDL
        .split('(')
        .filter_map(|ace| ace.strip_suffix(')'))
        .map(|ace| ace.split(';').collect::<Vec<_>>())
        .find(|fields| fields.get(5) == Some(&trustee))
        .map(|fields| {
            assert_eq!(fields[0], "A", "only allow ACEs");
            fields[2].to_owned()
        })
        .unwrap_or_default()
}

fn grants(rights: &str, right: &str) -> bool {
    rights.as_bytes().chunks(2).any(|pair| pair == right.as_bytes())
}

#[test]
fn only_system_can_stop_reconfigure_or_remove_the_service() {
    assert!(SERVICE_SDDL.starts_with("D:P"), "protected DACL, nothing inherited");
    let system = rights("SY");
    for right in ["WP", "DT", "DC", "SD", "WD", "WO", "RP", "LC", "CC"] {
        assert!(grants(&system, right), "SYSTEM lacks {right}");
    }
    // Administrators can look and start a stopped agent, never stop, change or delete it.
    let admins = rights("BA");
    for right in ["CC", "LC", "RP", "RC"] {
        assert!(grants(&admins, right), "Administrators lack {right}");
    }
    for right in ["WP", "DT", "DC", "SD", "WD", "WO"] {
        assert!(!grants(&admins, right), "Administrators must not have {right}");
    }
    let users = rights("AU");
    assert!(grants(&users, "LC"));
    for right in ["RP", "WP", "DT", "DC", "SD", "WD", "WO"] {
        assert!(!grants(&users, right), "authenticated users must not have {right}");
    }
    assert_eq!(SERVICE_SDDL.matches('(').count(), 3, "no other trustee");
}

#[test]
fn the_scheduled_watchdog_restores_a_disabled_or_stopped_service() {
    let healthy = ServiceSnapshot { automatic: true, running: true };
    assert!(watchdog_actions(Some(healthy), false).is_empty());
    assert_eq!(
        watchdog_actions(Some(ServiceSnapshot { automatic: false, running: false }), false),
        vec![WatchdogAction::MakeAutomatic, WatchdogAction::Start]
    );
    assert_eq!(
        watchdog_actions(Some(ServiceSnapshot { automatic: true, running: false }), false),
        vec![WatchdogAction::Start]
    );
    // Windows Installer is working (install, upgrade or removal): never interfere.
    assert!(watchdog_actions(Some(ServiceSnapshot { automatic: false, running: false }), true).is_empty());
    // Not installed: nothing to protect.
    assert!(watchdog_actions(None, false).is_empty());
}

struct Fake {
    present: Rc<Cell<bool>>,
    repairs: Rc<Cell<u32>>,
    repair_works: bool,
}

fn fake(kind: TamperKind, present: bool, repair_works: bool) -> (Check, Rc<Cell<bool>>, Rc<Cell<u32>>) {
    let state = Fake { present: Rc::new(Cell::new(present)), repairs: Rc::new(Cell::new(0)), repair_works };
    let (present, repairs) = (Rc::clone(&state.present), Rc::clone(&state.repairs));
    let check = Check::new(
        kind,
        {
            let present = Rc::clone(&state.present);
            move || Ok(present.get())
        },
        move || {
            state.repairs.set(state.repairs.get() + 1);
            if state.repair_works {
                state.present.set(true);
            }
            Ok(())
        },
    );
    (check, present, repairs)
}

#[test]
fn missing_protections_are_repaired_and_reported() {
    let log = TamperLog::default();
    let (rule, rule_present, rule_repairs) = fake(TamperKind::DnsRuleRestored, false, true);
    let (filters, _, filter_repairs) = fake(TamperKind::WfpRestored, true, true);
    let mut watchdog = Watchdog::new(vec![rule, filters]);
    let notes = watchdog.run(&log);
    assert!(rule_present.get());
    assert_eq!((rule_repairs.get(), filter_repairs.get()), (1, 0), "intact protections are left alone");
    assert!(notes.is_empty());
    let events = log.take().to_json()["events"].clone();
    assert_eq!(events.as_array().unwrap().len(), 1);
    assert_eq!(events[0]["kind"], json!("dns_rule_restored"));
}

#[test]
fn a_repair_that_does_not_stick_disables_its_check_instead_of_looping() {
    // If detection is wrong on some machine, repairing every cycle would flap the system and the panel.
    let log = TamperLog::default();
    let (rule, _, repairs) = fake(TamperKind::DnsRuleRestored, false, false);
    let mut watchdog = Watchdog::new(vec![rule]);
    let notes = watchdog.run(&log);
    assert_eq!(notes.len(), 1, "logged once");
    assert!(watchdog.run(&log).is_empty());
    assert_eq!(repairs.get(), 1);
    assert!(log.take().is_empty(), "nothing was restored");
}

#[test]
fn tamper_events_are_deduplicated_per_kind_and_bounded() {
    let log = TamperLog::with_capacity(2);
    let start: jiff::Timestamp = "2026-10-24T12:00:00Z".parse().unwrap();
    log.record_at(TamperKind::DnsRuleRestored, "NRPT rule recreated", start);
    // Same kind within 10 minutes: counted once.
    log.record_at(TamperKind::DnsRuleRestored, "NRPT rule recreated", start + jiff::SignedDuration::from_mins(9));
    log.record_at(TamperKind::DnsRuleRestored, "NRPT rule recreated", start + jiff::SignedDuration::from_mins(10));
    log.record_at(TamperKind::UnexpectedExit, "previous run ended without a graceful stop", start);
    let batch = log.take();
    assert_eq!(batch.dropped, 1, "capacity 2: the third event is counted, not kept");
    assert_eq!(
        batch.to_json()["events"],
        json!([
            {"at": "2026-10-24T12:00:00Z", "kind": "dns_rule_restored", "detail": "NRPT rule recreated"},
            {"at": "2026-10-24T12:10:00Z", "kind": "dns_rule_restored", "detail": "NRPT rule recreated"},
        ])
    );
    let again = TamperLog::default();
    again.record_at(TamperKind::WfpRestored, "x", start);
    let failed = again.take();
    again.restore(failed);
    assert_eq!(again.take().to_json()["events"][0]["kind"], json!("wfp_restored"));
}

#[test]
fn every_kind_has_the_wire_name_the_server_accepts() {
    let names: Vec<&str> = TamperKind::ALL.iter().map(|kind| kind.name()).collect();
    assert_eq!(
        names,
        vec![
            "dns_rule_restored",
            "wfp_restored",
            "browser_policy_restored",
            "hosts_restored",
            "service_config_restored",
            "watchdog_restored",
            "service_started_by_watchdog",
            "unexpected_exit",
        ]
    );
}

#[test]
fn a_run_marker_left_behind_reveals_an_unexpected_exit() {
    let directory = std::env::temp_dir().join(format!("openems-marker-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let marker = directory.join("running.marker");
    let _ = std::fs::remove_file(&marker);
    assert!(!begin_run(&marker).unwrap(), "first start");
    end_run(&marker).unwrap();
    assert!(!begin_run(&marker).unwrap(), "after a graceful stop");
    // Killed: no end_run.
    assert!(begin_run(&marker).unwrap(), "the previous run never stopped");
    end_run(&marker).unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn watchdog_events_written_by_the_scheduled_task_reach_the_service() {
    let directory = std::env::temp_dir().join(format!("openems-pending-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let pending = directory.join("tamper-pending.json");
    let _ = std::fs::remove_file(&pending);
    let at: jiff::Timestamp = "2026-10-24T12:00:00Z".parse().unwrap();
    openems_agent::tamper::append_pending(&pending, TamperKind::ServiceStartedByWatchdog, "service was stopped", at)
        .unwrap();
    openems_agent::tamper::append_pending(&pending, TamperKind::ServiceConfigRestored, "start type was disabled", at)
        .unwrap();
    let log = TamperLog::default();
    openems_agent::tamper::drain_pending(&pending, &log).unwrap();
    assert!(!pending.exists());
    let kinds: Vec<String> = log.take().to_json()["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["kind"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(kinds, vec!["service_started_by_watchdog", "service_config_restored"]);
    // A corrupt file is discarded rather than blocking the service start.
    std::fs::write(&pending, b"not json").unwrap();
    openems_agent::tamper::drain_pending(&pending, &log).unwrap();
    assert!(!pending.exists());
    std::fs::remove_dir_all(&directory).unwrap();
}
