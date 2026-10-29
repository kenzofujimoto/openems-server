//! First-match domain rules must agree with Python and require DNS enforcement.
use openems_agent::categories::NoCategories;
use openems_agent::policy::{WebFilter, validate_policy};
use serde_json::json;

#[test]
fn ordered_actions_and_log_reasons_override_later_matches() {
    let when = "2026-10-26T12:00:00Z".parse().unwrap();
    for action in ["allow", "block", "monitor"] {
        let body = validate_policy(&json!({"web_filter":{"domain_rules":[
            {"domain":"example.net","type":"simple","action":action},
            {"domain":"example.net","type":"wildcard","action":"block"}
        ]}})).unwrap();
        let filter = WebFilter::from_settings(&body["web_filter"]).unwrap();
        let result = filter.decision_at("www.example.net", when, &NoCategories).to_json();
        assert_eq!(result["action"], action);
        assert_eq!(result["log"], action != "allow");
        assert_eq!(result["reason"], if action == "allow" { json!(null) } else { json!("rule") });
        assert!(filter.requires_monitoring(), "ordered rules require the DNS path even without log actions");
    }
}

#[test]
fn malformed_or_ambiguous_ordered_policies_fail_validation() {
    for value in [json!(null), json!({}), json!([{"domain":"example.net","type":"regex","action":"block"}]),
        json!([{"domain":"*.example.net","type":"simple","action":"block"}]),
        json!([{"domain":"example.net","type":"simple","action":"log"}])] {
        assert!(validate_policy(&json!({"web_filter":{"domain_rules":value}})).is_err());
    }
    assert!(validate_policy(&json!({"web_filter":{"allowed":["example.net"],"domain_rules":[
        {"domain":"example.net","type":"simple","action":"block"}
    ]}})).is_err());
}

#[test]
fn empty_rules_and_wildcard_boundaries_do_not_invent_blocks() {
    let when = "2026-10-26T12:00:00Z".parse().unwrap();
    let body = validate_policy(&json!({"web_filter":{"domain_rules":[
        {"domain":"BÜCHER.de","type":"wildcard","action":"block"}
    ]}})).unwrap();
    assert_eq!(body["web_filter"]["domain_rules"][0]["domain"], "xn--bcher-kva.de");
    let filter = WebFilter::from_settings(&body["web_filter"]).unwrap();
    assert!(filter.blocks_at("a.xn--bcher-kva.de", when));
    assert!(!filter.blocks_at("otherxn--bcher-kva.de", when));
}
