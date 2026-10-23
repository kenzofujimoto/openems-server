//! Forced SafeSearch and scheduled answers from the local resolver, against a fake upstream.
use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use openems_agent::dns::{self, Decision, StaticUpstreams};
use openems_agent::https_blockpage::BlockedDomains;
use openems_agent::policy::{WebFilter, validate_policy};
use openems_agent::runtime::StopSignal;
use serde_json::json;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const SAFE_IP: Ipv4Addr = Ipv4Addr::new(216, 239, 38, 120);

fn filter(web_filter: serde_json::Value) -> Arc<BlockedDomains> {
    let body = validate_policy(&json!({ "web_filter": web_filter })).unwrap();
    let domains = Arc::new(BlockedDomains::default());
    domains.replace(WebFilter::from_settings(&body["web_filter"]).unwrap());
    domains
}

fn safe_search() -> Arc<BlockedDomains> {
    filter(json!({"safe_search": {"engines": ["google", "youtube", "bing", "duckduckgo"]}}))
}

fn query(name: &str, kind: RecordType) -> Vec<u8> {
    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    message.to_vec().unwrap()
}

#[test]
fn search_engines_are_rewritten_only_for_address_queries() {
    let rules = safe_search();
    for (name, target) in [
        ("www.google.com.", "forcesafesearch.google.com"),
        ("google.com.br.", "forcesafesearch.google.com"),
        ("www.youtube.com.", "restrict.youtube.com"),
        ("www.bing.com.", "strict.bing.com"),
        ("duckduckgo.com.", "safe.duckduckgo.com"),
    ] {
        for kind in [RecordType::A, RecordType::AAAA] {
            match dns::decide(&query(name, kind), &rules, true) {
                Decision::SafeSearch(found) => assert_eq!(found, target, "{name} {kind}"),
                other => panic!("{name} {kind}: expected SafeSearch, got {other:?}"),
            }
        }
        let Decision::Answer(bytes) = dns::decide(&query(name, RecordType::HTTPS), &rules, true) else {
            panic!("{name}: HTTPS records must be answered locally");
        };
        let reply = Message::from_vec(&bytes).unwrap();
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(reply.answers.is_empty(), "{name}: NODATA keeps browsers on the rewritten address");
    }
    assert!(matches!(dns::decide(&query("mail.google.com.", RecordType::A), &rules, true), Decision::Forward));
    let disabled = filter(json!({}));
    assert!(matches!(dns::decide(&query("www.google.com.", RecordType::A), &disabled, true), Decision::Forward));
}

#[test]
fn blocking_wins_over_safe_search_and_allowed_keeps_it() {
    let blocked = filter(json!({"blocked": ["*.google.com"], "safe_search": {"engines": ["google"]}}));
    assert!(matches!(dns::decide(&query("www.google.com.", RecordType::A), &blocked, true), Decision::Answer(_)));
    let allowed = filter(
        json!({"blocked": ["*.google.com"], "allowed": ["www.google.com"], "safe_search": {"engines": ["google"]}}),
    );
    assert!(matches!(dns::decide(&query("www.google.com.", RecordType::A), &allowed, true), Decision::SafeSearch(_)));
}

#[test]
fn schedule_decisions_follow_the_injected_clock() {
    let rules = filter(json!({
        "timezone": "America/Sao_Paulo",
        "scheduled": [{"blocked": ["*.facebook.com"], "days": ["mon"], "from": "08:00", "to": "18:00"}]
    }));
    let at = |text: &str| -> jiff::Timestamp { text.parse().unwrap() };
    assert!(rules.contains_at("www.facebook.com", at("2026-10-26T11:00:00Z")));
    assert!(!rules.contains_at("www.facebook.com", at("2026-10-26T21:00:00Z")));
}

/// Address, stop signal, worker and the names the fake upstream was asked for.
type Upstream = (SocketAddr, Arc<StopSignal>, std::thread::JoinHandle<()>, Arc<Mutex<Vec<String>>>);

/// Answers every query with SAFE_IP and records the names it was asked for.
fn logging_upstream(silent: bool) -> Upstream {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    let address = socket.local_addr().unwrap();
    let (stop, names) = (Arc::new(StopSignal::default()), Arc::new(Mutex::new(Vec::new())));
    let (worker_stop, worker_names) = (Arc::clone(&stop), Arc::clone(&names));
    let worker = std::thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        while !worker_stop.is_stopped() {
            let Ok((length, peer)) = socket.recv_from(&mut buffer) else { continue };
            let request = Message::from_vec(&buffer[..length]).unwrap();
            let name = request.queries[0].name().clone();
            worker_names.lock().unwrap().push(name.to_ascii());
            if silent {
                continue;
            }
            let mut reply = Message::response(request.metadata.id, OpCode::Query);
            reply.add_queries(request.queries.clone());
            reply.add_answer(Record::from_rdata(name, 300, RData::A(A(SAFE_IP))));
            socket.send_to(&reply.to_vec().unwrap(), peer).unwrap();
        }
    });
    (address, stop, worker, names)
}

fn exchange(rules: Arc<BlockedDomains>, upstream: SocketAddr, bytes: &[u8]) -> Message {
    let stop = Arc::new(StopSignal::default());
    let (bound, worker) = dns::start(
        &["127.0.0.1:0".parse().unwrap()],
        rules,
        true,
        Arc::new(StaticUpstreams(vec![upstream])),
        Arc::clone(&stop),
    )
    .unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    client.send_to(bytes, bound[0]).unwrap();
    let mut buffer = [0u8; 4096];
    let (length, _) = client.recv_from(&mut buffer).unwrap();
    stop.stop();
    worker.join().unwrap();
    Message::from_vec(&buffer[..length]).unwrap()
}

#[test]
fn safe_search_reply_is_a_cname_to_the_safe_host_with_its_addresses() {
    let (upstream, stop, worker, names) = logging_upstream(false);
    let request = query("www.google.com.", RecordType::A);
    let reply = exchange(safe_search(), upstream, &request);
    assert_eq!(reply.metadata.id, Message::from_vec(&request).unwrap().metadata.id);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(reply.queries, Message::from_vec(&request).unwrap().queries);
    let RData::CNAME(target) = &reply.answers[0].data else { panic!("first answer must be the CNAME: {reply:?}") };
    assert_eq!(target.0.to_ascii(), "forcesafesearch.google.com.");
    assert_eq!(reply.answers[0].name.to_ascii(), "www.google.com.");
    assert_eq!(reply.answers[1].name.to_ascii(), "forcesafesearch.google.com.");
    assert_eq!(reply.answers[1].data.to_string(), SAFE_IP.to_string());
    assert_eq!(
        *names.lock().unwrap(),
        vec!["forcesafesearch.google.com.".to_owned()],
        "the original name is never forwarded"
    );
    stop.stop();
    worker.join().unwrap();
}

#[test]
fn unreachable_safe_host_is_servfail_never_the_normal_engine() {
    let (upstream, stop, worker, names) = logging_upstream(true);
    let reply = exchange(safe_search(), upstream, &query("www.youtube.com.", RecordType::A));
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert!(reply.answers.is_empty());
    assert!(names.lock().unwrap().iter().all(|name| name == "restrict.youtube.com."));
    stop.stop();
    worker.join().unwrap();
}
