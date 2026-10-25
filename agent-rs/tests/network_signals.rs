use openems_agent::locations::Probe;
use openems_agent::network_signals;
use sha2::{Digest, Sha256};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn tls_probe(correct_pin: bool) -> (Probe, std::thread::JoinHandle<()>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pin = hex::encode(Sha256::digest(cert.cert.der()));
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let worker = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut server = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        while server.is_handshaking() {
            if server.complete_io(&mut socket).is_err() {
                break;
            }
        }
    });
    (Probe { host: "127.0.0.1".into(), port, sha256: if correct_pin { pin } else { "00".repeat(32) } }, worker)
}

#[test]
fn internal_probe_requires_the_exact_certificate_and_completes_a_real_tls_handshake() {
    let (probe, worker) = tls_probe(true);
    assert_eq!(network_signals::probe_certificate(&probe), Some(probe.sha256.clone()));
    worker.join().unwrap();
    let (probe, worker) = tls_probe(false);
    assert_eq!(network_signals::probe_certificate(&probe), None);
    worker.join().unwrap();
}

#[test]
fn a_peer_that_never_speaks_tls_is_unknown_after_two_seconds() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let probe =
        Probe { host: "127.0.0.1".into(), port: listener.local_addr().unwrap().port(), sha256: "00".repeat(32) };
    let started = Instant::now();
    assert_eq!(network_signals::probe_certificate(&probe), None);
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn adapter_collection_is_read_only_and_does_not_invent_a_public_address() {
    let observed = network_signals::collect(&[]).unwrap();
    assert!(observed.public_ip.is_none());
    for (address, prefix) in observed.addresses {
        assert!(!address.is_unspecified() && !address.is_loopback());
        assert!(u16::from(prefix) <= if address.is_ipv4() { 32 } else { 128 });
    }
    for mac in observed.gateway_macs {
        assert!(openems_agent::locations::normalize_mac(&mac).is_some());
    }
}

#[test]
fn an_unreachable_high_priority_probe_does_not_hide_a_healthy_later_location() {
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let first = Probe { host: "127.0.0.1".into(), port: silent.local_addr().unwrap().port(), sha256: "00".repeat(32) };
    let (second, worker) = tls_probe(true);
    let body = serde_json::json!({"web_filter": {"blocked": []}});
    let assignment = serde_json::json!({"vdom":"Office", "version":1, "digest":openems_agent::policy::policy_digest(body.as_object().unwrap()), "body":body});
    let definitions: Vec<_> = [&first, &second].into_iter().enumerate().map(|(index, probe)| {
        serde_json::json!({"id":format!("site-{index}"), "name":format!("Site {index}"), "dns_suffixes":["corp.example"],
            "probe":{"host":probe.host,"port":probe.port,"sha256":probe.sha256}, "assignment":assignment})
    }).collect();
    let locations = openems_agent::locations::parse_locations(&serde_json::json!({"locations":definitions})).unwrap();
    let started = Instant::now();
    let mut observed = network_signals::collect(&locations).unwrap();
    observed.dns_suffixes = vec!["corp.example".into()];
    assert_eq!(
        openems_agent::locations::choose(&locations, &observed).map(|location| location.id.as_str()),
        Some("site-1")
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    worker.join().unwrap();
}
