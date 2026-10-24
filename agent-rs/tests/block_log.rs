//! Block log: hourly aggregates of blocked DNS answers, bounded in memory.

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use openems_agent::categories::CategorySet;
use openems_agent::dns::{self, Decision};
use openems_agent::events::{BlockLog, EventReason, MAX_ROWS};
use openems_agent::https_blockpage::BlockedDomains;
use openems_agent::policy::WebFilter;
use serde_json::{Value, json};
use std::str::FromStr;

fn at(when: &str) -> jiff::Timestamp {
    when.parse().unwrap()
}

fn category(id: &str) -> EventReason {
    EventReason::Category(id.to_owned())
}

#[test]
fn repeated_queries_count_once_per_minute_in_hourly_rows() {
    let log = BlockLog::default();
    log.record_at("steamcommunity.com", &category("games"), at("2026-10-26T12:00:05Z"));
    // Browsers repeat the query (A, AAAA, retries): the same minute counts once.
    log.record_at("steamcommunity.com", &category("games"), at("2026-10-26T12:00:40Z"));
    log.record_at("steamcommunity.com", &category("games"), at("2026-10-26T12:01:00Z"));
    log.record_at("steamcommunity.com", &EventReason::Rule, at("2026-10-26T12:01:10Z"));
    log.record_at("steamcommunity.com", &category("games"), at("2026-10-26T13:10:00Z"));
    log.record_at("dns.google", &EventReason::Doh, at("2026-10-26T13:10:00Z"));
    let batch = log.take();
    assert_eq!(batch.dropped, 0);
    assert_eq!(
        batch.to_json()["events"],
        json!([
            {"hour": "2026-10-26T12:00:00Z", "domain": "steamcommunity.com", "reason": "category", "category": "games", "count": 2},
            {"hour": "2026-10-26T12:00:00Z", "domain": "steamcommunity.com", "reason": "rule", "count": 1},
            {"hour": "2026-10-26T13:00:00Z", "domain": "dns.google", "reason": "doh", "count": 1},
            {"hour": "2026-10-26T13:00:00Z", "domain": "steamcommunity.com", "reason": "category", "category": "games", "count": 1},
        ])
    );
    assert!(log.take().is_empty(), "take drains the log");
}

#[test]
fn a_full_log_counts_dropped_events_instead_of_growing() {
    assert_eq!(MAX_ROWS, 5000);
    let log = BlockLog::with_capacity(2);
    let now = at("2026-10-26T12:00:00Z");
    log.record_at("a.example", &EventReason::Rule, now);
    log.record_at("b.example", &EventReason::Rule, now);
    log.record_at("c.example", &EventReason::Rule, now);
    log.record_at("d.example", &EventReason::Rule, now);
    // Existing rows still count.
    log.record_at("a.example", &EventReason::Rule, at("2026-10-26T12:05:00Z"));
    let batch = log.take();
    assert_eq!(batch.dropped, 2);
    assert_eq!(batch.to_json()["dropped"], json!(2));
    assert_eq!(batch.to_json()["events"][0]["count"], json!(2));
    assert_eq!(batch.to_json()["events"].as_array().unwrap().len(), 2);
}

#[test]
fn a_failed_upload_is_restored_within_the_limit() {
    let log = BlockLog::with_capacity(2);
    let now = at("2026-10-26T12:00:00Z");
    log.record_at("a.example", &EventReason::Rule, now);
    log.record_at("b.example", &EventReason::Rule, now);
    let failed = log.take();
    log.record_at("a.example", &EventReason::Rule, at("2026-10-26T12:05:00Z"));
    log.record_at("c.example", &EventReason::Rule, at("2026-10-26T12:05:00Z"));
    log.restore(failed);
    let batch = log.take();
    let events = batch.to_json()["events"].clone();
    // a.example merges (1 + 1); b.example no longer fits and its count becomes dropped.
    assert_eq!(
        events,
        json!([
            {"hour": "2026-10-26T12:00:00Z", "domain": "a.example", "reason": "rule", "count": 2},
            {"hour": "2026-10-26T12:00:00Z", "domain": "c.example", "reason": "rule", "count": 1},
        ])
    );
    assert_eq!(batch.dropped, 1);
}

fn query(name: &str, kind: RecordType) -> Vec<u8> {
    let mut message = Message::query();
    message.add_query(Query::query(Name::from_str(name).unwrap(), kind));
    message.metadata.recursion_desired = true;
    message.to_vec().unwrap()
}

fn domains() -> BlockedDomains {
    let domains = BlockedDomains::default();
    let settings =
        json!({"blocked": ["example.com"], "blocked_categories": ["games"], "allowed": ["store.steampowered.com"]});
    domains.replace(WebFilter::from_settings(&settings).unwrap());
    domains.categories().insert("games", CategorySet::from_domains(&["steampowered.com".to_owned()]));
    domains.set_doh_blocking(true);
    domains
}

#[test]
fn the_resolver_logs_blocked_answers_with_their_reason() {
    let domains = domains();
    assert!(matches!(dns::decide(&query("www.example.com.", RecordType::A), &domains, false), Decision::Answer(_)));
    assert!(matches!(
        dns::decide(&query("api.steampowered.com.", RecordType::AAAA), &domains, false),
        Decision::Answer(_)
    ));
    assert!(matches!(dns::decide(&query("dns.google.", RecordType::A), &domains, false), Decision::Answer(_)));
    // Not logged: forwarded, allowed and the Firefox canary (a probe, not a block).
    assert!(matches!(
        dns::decide(&query("store.steampowered.com.", RecordType::A), &domains, false),
        Decision::Forward
    ));
    assert!(matches!(dns::decide(&query("example.org.", RecordType::A), &domains, false), Decision::Forward));
    dns::decide(&query("use-application-dns.net.", RecordType::A), &domains, false);
    let events = domains.block_log().take().to_json()["events"].clone();
    let rows: Vec<(String, String, Value)> = events
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["domain"].as_str().unwrap().to_owned(),
                row["reason"].as_str().unwrap().to_owned(),
                row["category"].clone(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        vec![
            ("api.steampowered.com".to_owned(), "category".to_owned(), json!("games")),
            ("dns.google".to_owned(), "doh".to_owned(), Value::Null),
            ("www.example.com".to_owned(), "rule".to_owned(), Value::Null),
        ]
    );
}

#[test]
fn the_block_page_names_the_category() {
    let domains = domains();
    assert_eq!(domains.category_label("api.steampowered.com"), Some("Jogos"));
    assert_eq!(domains.category_label("www.example.com"), None, "rules have no category");
    assert_eq!(domains.category_label("example.org"), None);
    let page = openems_agent::blockpage::render("api.steampowered.com", Some("Jogos <b>"));
    assert!(page.contains("Categoria: Jogos &lt;b&gt;"));
    assert!(!openems_agent::blockpage::render("www.example.com", None).contains("Categoria:"));
}
