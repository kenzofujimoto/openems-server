//! Public DNS-over-HTTPS/TLS endpoints, embedded from contract/doh-endpoints.json.
use crate::policy::normalize_domain;
use std::net::IpAddr;
use std::sync::OnceLock;

struct Endpoints {
    hosts: Vec<String>,
    addresses: Vec<IpAddr>,
}

fn endpoints() -> &'static Endpoints {
    static ENDPOINTS: OnceLock<Endpoints> = OnceLock::new();
    ENDPOINTS.get_or_init(|| {
        // The contract file is validated by tests/test_doh_endpoints.py; a bad entry is a build defect.
        let data: serde_json::Value =
            serde_json::from_str(include_str!("../../contract/doh-endpoints.json")).expect("embedded DoH list is JSON");
        let strings = |key: &str| -> Vec<String> {
            data[key]
                .as_array()
                .map(|items| items.iter().filter_map(|item| item.as_str().map(str::to_owned)).collect())
                .unwrap_or_default()
        };
        Endpoints {
            hosts: strings("hosts"),
            addresses: strings("addresses").iter().filter_map(|value| value.parse().ok()).collect(),
        }
    })
}

/// Addresses blocked on ports 443 and 853 by the anti-bypass network filters.
pub fn addresses() -> &'static [IpAddr] {
    &endpoints().addresses
}

/// A listed DoH host or one of its subdomains.
pub fn is_doh_host(name: &str) -> bool {
    let Ok(domain) = normalize_domain(name) else { return false };
    endpoints()
        .hosts
        .iter()
        .any(|host| domain == *host || domain.strip_suffix(host.as_str()).is_some_and(|prefix| prefix.ends_with('.')))
}
