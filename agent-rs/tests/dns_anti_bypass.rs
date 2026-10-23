//! Anti-bypass behaviour that needs no system changes: DoH endpoint list and resolver answers.
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use openems_agent::dns::{self, Decision};
use openems_agent::doh;
use openems_agent::https_blockpage::BlockedDomains;
use std::net::IpAddr;

fn query(name: &str) -> Vec<u8> {
    let mut message = Message::query();
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    message.to_vec().unwrap()
}

#[test]
fn embedded_list_matches_the_contract_file() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../contract/doh-endpoints.json")).unwrap();
    let data: serde_json::Value = serde_json::from_str(&text).unwrap();
    let addresses: Vec<IpAddr> =
        data["addresses"].as_array().unwrap().iter().map(|value| value.as_str().unwrap().parse().unwrap()).collect();
    assert_eq!(doh::addresses(), addresses.as_slice());
    for host in data["hosts"].as_array().unwrap() {
        assert!(doh::is_doh_host(host.as_str().unwrap()), "{host}");
    }
}

#[test]
fn doh_hosts_match_names_and_their_subdomains_only() {
    assert!(doh::is_doh_host("dns.google"));
    assert!(doh::is_doh_host("DNS.Google"));
    assert!(doh::is_doh_host("abc123.dns.nextdns.io"));
    for name in ["google.com", "notdns.google", "example.org", "cloudflare.com", "not a name"] {
        assert!(!doh::is_doh_host(name), "{name}");
    }
}

#[test]
fn resolver_answers_doh_names_with_nxdomain_only_when_enabled() {
    let domains = BlockedDomains::default();
    assert!(matches!(dns::decide(&query("dns.google."), &domains, true), Decision::Forward));
    domains.set_doh_blocking(true);
    let Decision::Answer(bytes) = dns::decide(&query("dns.google."), &domains, true) else {
        panic!("DoH names must be answered locally");
    };
    assert_eq!(Message::from_vec(&bytes).unwrap().metadata.response_code, ResponseCode::NXDomain);
    assert!(matches!(dns::decide(&query("example.org."), &domains, true), Decision::Forward));
}
