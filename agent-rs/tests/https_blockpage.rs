use openems_agent::https_blockpage::BlockedDomains;
use openems_agent::{authority::Authority, https_blockpage, runtime::StopSignal};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};

fn client(
    address: SocketAddr,
    root: rustls::pki_types::CertificateDer<'static>,
    sni: &str,
) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    client_with_sni(address, root, sni, true)
}

fn client_with_sni(
    address: SocketAddr,
    root: rustls::pki_types::CertificateDer<'static>,
    sni: &str,
    enable_sni: bool,
) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root).unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.enable_sni = enable_sni;
    let connection = rustls::ClientConnection::new(Arc::new(config), sni.to_owned().try_into().unwrap()).unwrap();
    let socket = TcpStream::connect(address).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    rustls::StreamOwned::new(connection, socket)
}

fn response(
    mut client: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    host: &str,
) -> std::io::Result<String> {
    client.write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())?;
    let mut response = String::new();
    client.read_to_string(&mut response)?;
    Ok(response)
}

#[test]
fn real_tls_requires_correct_authority_blocked_sni_and_matching_host() {
    let authority = Authority::ephemeral().unwrap();
    let root = authority.root_der();
    let allowed = Arc::new(BlockedDomains::default());
    allowed.replace(&["example.com".into()]).unwrap();
    let stop = Arc::new(StopSignal::default());
    let (address, worker) = https_blockpage::start(0, authority, Arc::clone(&allowed), Arc::clone(&stop)).unwrap();
    let page = response(client(address, root.clone(), "example.com"), "example.com").unwrap();
    assert!(page.starts_with("HTTP/1.1 200 OK") && page.contains("Acesso bloqueado"));
    assert!(response(client(address, root.clone(), "example.com"), "allowed.com").unwrap().starts_with("HTTP/1.1 421"));
    assert!(
        response(client(address, root.clone(), "example.com"), "example.com\r\nHost: example.com")
            .unwrap()
            .starts_with("HTTP/1.1 421")
    );
    assert!(response(client(address, root.clone(), "allowed.com"), "allowed.com").is_err());
    assert!(response(client_with_sni(address, root.clone(), "example.com", false), "example.com").is_err());
    let unrelated = Authority::ephemeral().unwrap();
    assert!(response(client(address, unrelated.root_der(), "example.com"), "example.com").is_err());
    // An already established connection must also lose access after policy release.
    let mut established = client(address, root.clone(), "example.com");
    established.conn.complete_io(&mut established.sock).unwrap();
    allowed.replace(&[]).unwrap();
    assert!(response(established, "example.com").unwrap().starts_with("HTTP/1.1 421"));
    assert!(response(client(address, root, "example.com"), "example.com").is_err());
    stop.stop();
    worker.join().unwrap();
    assert!(TcpStream::connect(address).is_err());
}

#[test]
fn port_conflict_fails_before_start_and_idle_peers_drain_on_stop() {
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reserved.local_addr().unwrap().port();
    let allowed = Arc::new(BlockedDomains::default());
    let stop = Arc::new(StopSignal::default());
    assert!(
        https_blockpage::start(port, Authority::ephemeral().unwrap(), Arc::clone(&allowed), Arc::clone(&stop)).is_err()
    );
    let (address, worker) =
        https_blockpage::start(0, Authority::ephemeral().unwrap(), allowed, Arc::clone(&stop)).unwrap();
    let sockets: Vec<_> = (0..8).map(|_| TcpStream::connect(address).unwrap()).collect();
    std::thread::sleep(Duration::from_millis(100));
    let started = std::time::Instant::now();
    stop.stop();
    worker.join().unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
    drop(sockets);
}

#[test]
fn certificates_are_limited_to_exact_redirected_domains_and_release_revokes() {
    let domains = BlockedDomains::default();
    assert!(!domains.contains("example.com"));
    domains.replace(&["example.com".into()]).unwrap();
    assert!(domains.contains("example.com"));
    assert!(domains.contains("www.example.com"));
    for name in ["allowed.com", "sub.example.com", "127.0.0.1", "example.com.", "https://example.com"] {
        assert!(!domains.contains(name), "{name}");
    }
    assert!(domains.replace(&["*.example.com".into()]).is_err());
    assert!(domains.contains("example.com"));
    domains.replace(&[]).unwrap();
    assert!(!domains.contains("example.com"));
}
