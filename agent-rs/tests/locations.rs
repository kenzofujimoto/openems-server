//! Network locations (network-locations.md): when the machine is inside a company location and which
//! policy then applies. "In doubt, outside": anything unknown keeps the stricter outside policy.

use openems_agent::locations::{Observed, choose, parse_locations};
use openems_agent::policy::validate_assignment;
use serde_json::{Value, json};

fn assignment(vdom: &str) -> Value {
    let body = json!({"web_filter": {"blocked": []}});
    let digest = openems_agent::policy::policy_digest(body.as_object().unwrap());
    json!({"vdom": vdom, "version": 1, "digest": digest, "body": body})
}

fn office(signals: Value) -> Value {
    let mut location = json!({"id": "sp", "name": "Escritório SP", "cidrs": [], "gateway_macs": [],
                              "dns_suffixes": [], "public_cidrs": [], "probe": null, "assignment": assignment("Office")});
    for (key, value) in signals.as_object().unwrap() {
        location[key] = value.clone();
    }
    location
}

fn response(locations: Vec<Value>) -> Value {
    let mut outside = assignment("Default");
    outside["locations"] = Value::Array(locations);
    outside["client_ip"] = json!("200.1.2.3");
    outside
}

fn at_home() -> Observed {
    Observed {
        addresses: vec![("192.168.1.20".parse().unwrap(), 24)],
        gateway_macs: vec!["aa-bb-cc-00-00-01".into()],
        dns_suffixes: vec!["home".into()],
        public_ip: Some("189.10.10.10".parse().unwrap()),
        probes: Default::default(),
    }
}

fn locations(signals: Value) -> Vec<openems_agent::locations::Location> {
    let raw = response(vec![office(signals)]);
    parse_locations(&validate_assignment(&raw).unwrap().raw).unwrap()
}

#[test]
fn the_office_public_address_alone_is_enough() {
    let parsed = locations(json!({"public_cidrs": ["200.1.2.0/24"]}));
    let mut observed = at_home();
    assert!(choose(&parsed, &observed).is_none());
    observed.public_ip = Some("200.1.2.3".parse().unwrap());
    assert_eq!(choose(&parsed, &observed).unwrap().id, "sp");
}

#[test]
fn two_local_signals_are_needed_and_a_home_network_with_the_same_range_is_not_the_office() {
    let parsed = locations(json!({"cidrs": ["192.168.1.0/24"], "gateway_macs": ["00:11:22:33:44:55"]}));
    let mut observed = at_home();
    assert!(choose(&parsed, &observed).is_none(), "same range, different gateway: home");
    observed.gateway_macs = vec!["00-11-22-33-44-55".into()];
    assert_eq!(choose(&parsed, &observed).unwrap().id, "sp", "MAC formats are compared normalized");
}

#[test]
fn dns_suffixes_and_the_internal_certificate_count_as_signals() {
    let pin = "ab".repeat(32);
    let parsed = locations(json!({"dns_suffixes": ["Corp.Example."], "probe": {"host": "intranet.corp.example", "port": 443, "sha256": pin}}));
    let mut observed = at_home();
    observed.dns_suffixes = vec!["corp.example".into()];
    assert!(choose(&parsed, &observed).is_none(), "one signal is not enough");
    observed.probes.insert(("intranet.corp.example".into(), 443), Some("AB".repeat(32)));
    assert_eq!(choose(&parsed, &observed).unwrap().id, "sp");
    observed.probes.insert(("intranet.corp.example".into(), 443), None);
    assert!(choose(&parsed, &observed).is_none(), "an unreachable probe does not match");
}

#[test]
fn unknown_signals_never_match() {
    let parsed = locations(json!({"public_cidrs": ["200.1.2.0/24"], "cidrs": ["10.0.0.0/8"]}));
    let observed = Observed { addresses: vec![], gateway_macs: vec![], dns_suffixes: vec![], public_ip: None, probes: Default::default() };
    assert!(choose(&parsed, &observed).is_none());
}

#[test]
fn ipv6_ranges_match_and_the_first_matching_location_wins() {
    let raw = response(vec![
        json!({"id": "a", "name": "A", "cidrs": ["2001:db8::/32"], "gateway_macs": ["00-00-00-00-00-01"], "dns_suffixes": [],
               "public_cidrs": [], "probe": null, "assignment": assignment("A")}),
        json!({"id": "b", "name": "B", "cidrs": [], "gateway_macs": [], "dns_suffixes": [], "public_cidrs": ["0.0.0.0/0"],
               "probe": null, "assignment": assignment("B")}),
    ]);
    let parsed = parse_locations(&validate_assignment(&raw).unwrap().raw).unwrap();
    let mut observed = at_home();
    observed.addresses.push(("2001:db8::7".parse().unwrap(), 64));
    observed.gateway_macs.push("00:00:00:00:00:01".into());
    assert_eq!(choose(&parsed, &observed).unwrap().id, "a");
    assert_eq!(choose(&parsed, &observed).unwrap().assignment.vdom, "A");
}

#[test]
fn a_location_with_a_tampered_policy_is_skipped_and_others_still_work() {
    let mut bad = office(json!({"public_cidrs": ["0.0.0.0/0"]}));
    bad["id"] = json!("bad");
    bad["assignment"]["body"] = json!({"web_filter": {"blocked": ["evil.example"]}});
    let good = office(json!({"public_cidrs": ["189.10.0.0/16"]}));
    let raw = response(vec![bad, good]);
    let parsed = parse_locations(&validate_assignment(&raw).unwrap().raw).unwrap();
    assert_eq!(parsed.iter().map(|location| location.id.as_str()).collect::<Vec<_>>(), vec!["sp"]);
    assert_eq!(choose(&parsed, &at_home()).unwrap().id, "sp");
}

#[test]
fn malformed_definitions_are_skipped_and_an_old_server_sends_none() {
    let raw = response(vec![json!({"id": "x", "name": "X", "cidrs": ["not-a-range"], "gateway_macs": [], "dns_suffixes": [],
                                   "public_cidrs": [], "probe": null, "assignment": assignment("X")})]);
    assert!(parse_locations(&validate_assignment(&raw).unwrap().raw).unwrap().is_empty());
    assert!(parse_locations(&assignment("Default")).unwrap().is_empty());
}

#[test]
fn the_server_reported_public_address_is_read_from_the_response() {
    let raw = response(vec![]);
    assert_eq!(openems_agent::locations::client_ip(&raw), Some("200.1.2.3".parse().unwrap()));
    assert_eq!(openems_agent::locations::client_ip(&assignment("Default")), None);
}
