use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use openems_agent::categories::{CategorySet, CategoryStore};
use openems_agent::dns::{self, Decision};
use openems_agent::events::{BlockLog, EventReason};
use openems_agent::https_blockpage::BlockedDomains;
use openems_agent::policy::{WebFilter, policy_digest, validate_assignment, validate_policy};
use serde_json::{Value, json};

fn filter(settings: Value) -> WebFilter {
    let policy = validate_policy(&json!({"web_filter": settings})).unwrap();
    WebFilter::from_settings(&policy["web_filter"]).unwrap()
}

fn now() -> jiff::Timestamp {
    "2026-10-26T12:00:00Z".parse().unwrap()
}

fn store() -> CategoryStore {
    let store = CategoryStore::default();
    for id in ["games", "streaming", "adult"] {
        store.insert(id, CategorySet::from_domains(&["shared.example".into()]));
    }
    store
}

#[test]
fn actions_have_explicit_precedence_and_allowed_exceptions_suppress_logging() {
    let filter = filter(json!({"category_actions":{"games":"allow","streaming":"monitor","adult":"block"},
        "allowed":["*.safe.shared.example"]}));
    assert_eq!(
        filter.decision_at("shared.example", now(), &store()).to_json(),
        json!({"action":"block","reason":"category","category":"adult","log":true})
    );
    assert_eq!(
        filter.decision_at("safe.shared.example", now(), &store()).to_json(),
        json!({"action":"allow","reason":null,"category":null,"log":false})
    );
    assert_eq!(filter.referenced_categories(), vec!["adult", "games", "streaming"]);
}

#[test]
fn monitor_all_preserves_explicit_category_allow_and_never_claims_unknown_classification() {
    let filter = filter(json!({"category_actions":{"games":"allow"},"monitor_all":true}));
    assert_eq!(
        filter.decision_at("shared.example", now(), &store()).to_json(),
        json!({"action":"allow","reason":"category","category":"games","log":false})
    );
    assert_eq!(
        filter.decision_at("other.example", now(), &store()).to_json(),
        json!({"action":"monitor","reason":"observation","category":null,"log":true})
    );
    assert_eq!(filter.referenced_categories(), vec!["games"], "allow category needs data when suppressing monitor_all");
    assert_eq!(
        filter.decision_at("shared.example", now(), &CategoryStore::default()).to_json(),
        json!({"action":"monitor","reason":"observation","category":null,"log":true})
    );
}

#[test]
fn scheduled_actions_add_to_permanent_rules_and_legacy_categories_keep_meaning() {
    let filter = filter(json!({"blocked_categories":["adult"],"timezone":"UTC",
        "scheduled":[{"days":["mon"],"from":"10:00","to":"13:00","category_actions":{"games":"monitor"}}]}));
    let store = CategoryStore::default();
    store.insert("games", CategorySet::from_domains(&["games.example".into()]));
    assert_eq!(filter.decision_at("games.example", now(), &store).to_json()["action"], "monitor");
    assert_eq!(
        filter.decision_at("games.example", "2026-10-26T14:00:00Z".parse().unwrap(), &store).to_json()["action"],
        "allow"
    );
    assert_eq!(filter.referenced_categories(), vec!["adult", "games"]);
    assert_eq!(filter.active_categories(now()), vec!["adult"]);
}

#[test]
fn invalid_actions_and_contradictory_legacy_settings_are_rejected() {
    for settings in [
        json!({"category_actions":{"games":"log"}}),
        json!({"category_actions":{"fake":"block"}}),
        json!({"category_actions":[]}),
        json!({"monitor_all":"true"}),
        json!({"blocked_categories":["games"],"category_actions":{"games":"allow"}}),
    ] {
        assert!(validate_policy(&json!({"web_filter":settings})).is_err());
    }
    assert!(
        validate_policy(&json!({"web_filter":{"blocked_categories":["games"],"category_actions":{"games":"block"}}}))
            .is_ok()
    );
}

fn query(name: &str) -> Vec<u8> {
    let mut query = Message::query();
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    query.to_vec().unwrap()
}

#[test]
fn dns_monitoring_forwards_without_a_block_page_and_distinguishes_blocked_events() {
    let domains = BlockedDomains::default();
    domains.replace(filter(json!({"category_actions":{"games":"monitor"},"blocked":["blocked.example"],
        "allowed":["safe.shared.example"]})));
    domains.categories().insert("games", CategorySet::from_domains(&["shared.example".into()]));
    assert!(matches!(dns::decide(&query("shared.example"), &domains, false), Decision::Forward));
    assert!(!domains.contains("shared.example"));
    assert!(matches!(dns::decide(&query("safe.shared.example"), &domains, false), Decision::Forward));
    assert!(matches!(dns::decide(&query("blocked.example"), &domains, false), Decision::Answer(_)));
    let rows = domains.block_log().take().to_json()["events"].as_array().unwrap().clone();
    assert_eq!(rows.len(), 2);
    let monitored = rows.iter().find(|row| row["domain"] == "shared.example").unwrap();
    assert_eq!(monitored["action"], "monitored");
    assert_eq!(monitored["source"], "dns");
    assert_eq!(monitored["category"], "games");
}

#[test]
fn retried_upload_retains_batch_identity_and_does_not_merge_new_observations() {
    let log = BlockLog::with_capacity(2);
    log.record_at("first.example", &EventReason::Rule, now());
    let first = log.begin_upload();
    let first_json = first.to_json();
    assert_eq!(first_json["batch_id"].as_str().unwrap().len(), 64);
    log.record_at("second.example", &EventReason::Rule, now());
    log.record_at("third.example", &EventReason::Rule, now());
    assert_eq!(log.begin_upload().to_json(), first_json);
    log.finish_upload(first_json["batch_id"].as_str().unwrap());
    let next = log.begin_upload().to_json();
    assert_ne!(next["batch_id"], first_json["batch_id"]);
    assert_eq!(next["events"].as_array().unwrap().len(), 1);
    assert_eq!(next["events"][0]["domain"], "second.example");
    assert_eq!(next["dropped"], 1);
}

#[test]
fn monitor_policy_is_not_successfully_enforced_in_hosts_only_mode() {
    use openems_agent::config::AgentConfig;
    use openems_agent::runtime::{Logger, enforce};
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = AgentConfig::new("http://127.0.0.1:9", "monitor-test");
    cfg.hosts_path = dir.path().join("hosts");
    std::fs::write(&cfg.hosts_path, "# baseline\n").unwrap();
    let body = json!({"web_filter":{"monitor_all":true}});
    let assignment = validate_assignment(&json!({"vdom":"Default","version":1,
        "digest":policy_digest(body.as_object().unwrap()),"body":body}))
    .unwrap();
    let logger: Logger = Arc::new(|_| {});
    assert!(enforce(&cfg, &assignment, &logger).is_err());
    assert_eq!(std::fs::read_to_string(&cfg.hosts_path).unwrap(), "# baseline\n");
}
