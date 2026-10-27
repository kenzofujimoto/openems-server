use super::*;

#[test]
fn one_minute_unique_domain_flood_keeps_deduplication_bounded() {
    let log = BlockLog::with_capacity(2);
    let now = "2026-10-26T12:00:00Z".parse().unwrap();
    for n in 0..1000 {
        log.record_action_at(&format!("domain{n}.example"), &EventReason::Policy, "monitored", now);
    }
    let state = log.lock();
    assert!(state.recent.len() <= 4, "deduplication cache must obey its hard limit");
    assert_eq!(state.rows.len(),2);
    assert_eq!(state.dropped,998);
}
