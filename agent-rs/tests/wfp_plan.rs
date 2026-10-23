//! Anti-bypass network filters as data: WFP arbitration inside the agent sublayer is simulated
//! (highest-weight matching filter wins). The machine's WFP is never touched here.
use openems_agent::wfp::{Action, Connection, plan, verdict};
use std::net::IpAddr;

fn connection(remote: &str, port: u16, loopback: bool, agent: bool) -> Connection {
    Connection { remote: remote.parse().unwrap(), port, loopback, agent }
}

fn doh() -> Vec<IpAddr> {
    ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"].iter().map(|ip| ip.parse().unwrap()).collect()
}

#[test]
fn windows_dns_client_reaches_the_local_resolver_and_the_agent_reaches_upstreams() {
    let filters = plan(&doh());
    for (remote, port) in [("127.0.0.1", 53), ("::1", 53), ("127.0.0.1", 853)] {
        assert_eq!(verdict(&filters, &connection(remote, port, true, false)), Some(Action::Permit), "{remote}:{port}");
    }
    for remote in ["192.168.1.1", "8.8.8.8", "fe80::1", "2001:4860:4860::8888"] {
        assert_eq!(verdict(&filters, &connection(remote, 53, false, true)), Some(Action::Permit), "agent to {remote}");
    }
}

#[test]
fn other_programs_cannot_query_dns_or_dot_directly() {
    let filters = plan(&doh());
    for remote in ["192.168.1.1", "8.8.8.8", "9.9.9.9", "2001:4860:4860::8888"] {
        for port in [53, 853] {
            assert_eq!(
                verdict(&filters, &connection(remote, port, false, false)),
                Some(Action::Block),
                "{remote}:{port}"
            );
        }
    }
}

#[test]
fn known_doh_addresses_are_blocked_on_https_and_dot_ports_for_everyone() {
    let filters = plan(&doh());
    for remote in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
        for port in [443, 853] {
            for agent in [false, true] {
                let expected = if agent && port == 853 { Action::Permit } else { Action::Block };
                assert_eq!(
                    verdict(&filters, &connection(remote, port, false, agent)),
                    Some(expected),
                    "{remote}:{port} agent={agent}"
                );
            }
        }
    }
}

#[test]
fn ordinary_web_traffic_is_left_alone() {
    let filters = plan(&doh());
    for (remote, port) in
        [("93.184.216.34", 443), ("1.1.1.1", 80), ("2606:2800:220:1::248", 443), ("192.168.1.10", 445)]
    {
        assert_eq!(verdict(&filters, &connection(remote, port, false, false)), None, "{remote}:{port}");
    }
}

#[test]
fn every_filter_targets_one_address_family_layer() {
    let filters = plan(&doh());
    assert!(filters.iter().any(|filter| filter.v6) && filters.iter().any(|filter| !filter.v6));
    for filter in &filters {
        for address in filter.addresses() {
            assert_eq!(address.is_ipv6(), filter.v6, "{}", filter.name);
        }
    }
    // 2 families x (loopback permit + 2 ports x (agent permit + block)) + 3 addresses x 2 ports.
    assert_eq!(filters.len(), 2 * (1 + 2 * 2) + 3 * 2);
}
