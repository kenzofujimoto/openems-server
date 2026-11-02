//! Warning action: local page, single-use continue tokens and DNS answers.
use openems_agent::categories::CategorySet;
use openems_agent::https_blockpage::{self, BlockedDomains};
use openems_agent::policy::{WebAction, WebFilter, validate_policy};
use openems_agent::{authority::Authority, blockpage, dns, runtime::StopSignal};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

fn domains(policy: serde_json::Value) -> Arc<BlockedDomains> {
    let validated = validate_policy(&serde_json::json!({ "web_filter": policy })).unwrap();
    let blocked = Arc::new(BlockedDomains::default());
    blocked.replace(WebFilter::from_settings(&validated["web_filter"]).unwrap());
    blocked
        .categories()
        .insert("streaming", CategorySet::from_domains(&["video.example".into(), "clips.example".into()]));
    blocked.categories().insert("adult", CategorySet::from_domains(&["adult.example".into()]));
    blocked
}

fn token(page: &str) -> String {
    let start = page.find("?token=").expect("warning form") + 7;
    page[start..start + 64].to_owned()
}

#[test]
fn warning_page_continues_once_for_the_whole_category() {
    let blocked = domains(serde_json::json!({ "category_actions": { "streaming": "warn", "adult": "block" } }));
    assert!(blocked.warns("video.example") && blocked.contains("video.example"));
    let page = blockpage::respond("GET / HTTP/1.1\r\n\r\n", "video.example", &blocked);
    assert!(page.contains("Continuar mesmo assim") && page.contains("Categoria: Áudio e vídeo"));
    let issued = token(&page);
    // Another host, a forged token or a blocked category never continue.
    assert!(!blocked.proceed("adult.example", &blocked.issue_token("adult.example")));
    assert!(!blocked.proceed("clips.example", &issued));
    let page = blockpage::respond("GET / HTTP/1.1\r\n\r\n", "video.example", &blocked);
    let issued = token(&page);
    let request = format!("POST {}?token={issued} HTTP/1.1\r\n\r\n", blockpage::PROCEED_PATH);
    assert!(blockpage::respond(&request, "video.example", &blocked).contains("Acesso liberado"));
    // The token is single use, and the continue covers every site of the category.
    assert!(!blocked.proceed("video.example", &issued));
    assert!(!blocked.warns("clips.example") && !blocked.contains("clips.example"));
    assert_eq!(blocked.decision("clips.example").action, WebAction::Monitor);
    assert!(blocked.decision("clips.example").log);
    assert!(blocked.contains("adult.example") && !blocked.warns("adult.example"));
}

#[test]
fn domain_rule_warnings_continue_per_domain_and_reject_malformed_tokens() {
    let blocked = domains(serde_json::json!({ "domain_rules": [
        { "domain": "a.example", "type": "simple", "action": "warn" },
        { "domain": "b.example", "type": "simple", "action": "warn" }
    ] }));
    let issued = blocked.issue_token("a.example");
    assert!(blockpage::proceed_token("POST /__openems/proceed?token=zz HTTP/1.1").is_none());
    assert!(blockpage::proceed_token("GET /__openems/proceed?token=00 HTTP/1.1").is_none());
    assert!(blocked.proceed("A.example", &issued));
    assert!(!blocked.warns("a.example") && blocked.warns("b.example"));
}

#[test]
fn dns_answers_a_warning_locally_with_a_short_ttl_until_continued() {
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RecordType};
    let blocked = domains(serde_json::json!({ "category_actions": { "streaming": "warn" } }));
    let mut query = Message::query();
    query.add_query(Query::query(Name::from_ascii("video.example.").unwrap(), RecordType::A));
    let bytes = query.to_vec().unwrap();
    let answer = |blocked: &BlockedDomains| match dns::decide(&bytes, blocked, true) {
        dns::Decision::Answer(reply) => Some(Message::from_vec(&reply).unwrap()),
        _ => None,
    };
    let reply = answer(&blocked).expect("local answer");
    assert_eq!(reply.answers[0].ttl, 2);
    assert!(blocked.proceed("video.example", &blocked.issue_token("video.example")));
    assert!(answer(&blocked).is_none(), "continued warnings are forwarded");
}

#[test]
fn http_and_https_pages_serve_the_warning_and_accept_the_form() {
    let blocked = domains(serde_json::json!({ "category_actions": { "streaming": "warn" } }));
    let stop = Arc::new(StopSignal::default());
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let worker = blockpage::start(port, Arc::clone(&blocked), Arc::clone(&stop)).unwrap();
    let send = |request: String| {
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        client.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        response
    };
    let page = send("GET / HTTP/1.1\r\nHost: video.example\r\n\r\n".into());
    assert!(page.contains("Continuar mesmo assim"));
    let done = send(format!(
        "POST {}?token={} HTTP/1.1\r\nHost: video.example\r\n\r\n",
        blockpage::PROCEED_PATH,
        token(&page)
    ));
    assert!(done.contains("Acesso liberado") && done.contains("http-equiv=\"refresh\""));
    stop.stop();
    worker.join().unwrap();

    let warned = domains(serde_json::json!({ "category_actions": { "streaming": "warn" } }));
    let authority = Authority::ephemeral().unwrap();
    let root = authority.root_der();
    let stop = Arc::new(StopSignal::default());
    let (address, worker) = https_blockpage::start(0, authority, Arc::clone(&warned), Arc::clone(&stop)).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root).unwrap();
    let config = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let tls = |request: String| {
        let connection =
            rustls::ClientConnection::new(Arc::clone(&config), "video.example".try_into().unwrap()).unwrap();
        let socket = TcpStream::connect(address).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut stream = rustls::StreamOwned::new(connection, socket);
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        response
    };
    let page = tls("GET / HTTP/1.1\r\nHost: video.example\r\n\r\n".into());
    assert!(page.starts_with("HTTP/1.1 200 OK") && page.contains("Continuar mesmo assim"), "{page}");
    let done =
        tls(format!("POST {}?token={} HTTP/1.1\r\nHost: video.example\r\n\r\n", blockpage::PROCEED_PATH, token(&page)));
    assert!(done.contains("Acesso liberado"), "{done}");
    assert!(!warned.contains("video.example"));
    stop.stop();
    worker.join().unwrap();
}
