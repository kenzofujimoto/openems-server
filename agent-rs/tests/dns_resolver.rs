//! Local DNS resolver: blocked answers, forwarding to a fake upstream on ephemeral ports.
//! Nothing here touches the machine DNS configuration.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use openems_agent::dns::{self, Decision, StaticUpstreams};
use openems_agent::https_blockpage::BlockedDomains;
use openems_agent::policy::WebRules;
use openems_agent::runtime::StopSignal;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

const UPSTREAM_IP: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

fn blocked(rules: &[&str], allowed: &[&str]) -> Arc<BlockedDomains> {
    let owned = |items: &[&str]| items.iter().map(|item| (*item).to_owned()).collect::<Vec<_>>();
    let domains = Arc::new(BlockedDomains::default());
    domains.replace(WebRules::new(&owned(rules), &owned(allowed)).unwrap());
    domains
}

fn query(name: &str, kind: RecordType) -> Vec<u8> {
    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    message.to_vec().unwrap()
}

fn answer(decision: Decision) -> Message {
    match decision {
        Decision::Answer(bytes) => Message::from_vec(&bytes).unwrap(),
        other => panic!("expected a local answer, got {other:?}"),
    }
}

fn addresses(message: &Message) -> Vec<String> {
    message.answers.iter().map(|record| record.data.to_string()).collect()
}

#[test]
fn blocked_names_get_loopback_or_null_answers_with_short_ttl() {
    let rules = blocked(&["*.example.com"], &[]);
    let bytes = query("a.example.com.", RecordType::A);
    let request = Message::from_vec(&bytes).unwrap();
    let reply = answer(dns::decide(&bytes, &rules, true));
    assert_eq!(reply.metadata.id, request.metadata.id);
    assert_eq!(reply.metadata.message_type, MessageType::Response);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.metadata.recursion_available);
    assert_eq!(reply.queries, request.queries);
    assert_eq!(addresses(&reply), vec!["127.0.0.1"]);
    assert_eq!(reply.answers[0].ttl, 30);
    assert_eq!(addresses(&answer(dns::decide(&query("example.com.", RecordType::AAAA), &rules, true))), vec!["::1"]);
    assert_eq!(addresses(&answer(dns::decide(&query("example.com.", RecordType::A), &rules, false))), vec!["0.0.0.0"]);
    assert_eq!(addresses(&answer(dns::decide(&query("Example.COM.", RecordType::AAAA), &rules, false))), vec!["::"]);
}

#[test]
fn other_record_types_for_blocked_names_get_no_data() {
    let rules = blocked(&["example.com"], &[]);
    for kind in [RecordType::HTTPS, RecordType::SVCB, RecordType::MX, RecordType::TXT, RecordType::CNAME] {
        let reply = answer(dns::decide(&query("www.example.com.", kind), &rules, true));
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError, "{kind}");
        assert!(reply.answers.is_empty(), "{kind}");
    }
}

#[test]
fn allowed_and_unlisted_names_are_forwarded() {
    let rules = blocked(&["*.google.com"], &["mail.google.com"]);
    for name in ["mail.google.com.", "example.org.", "google.com.br."] {
        assert!(matches!(dns::decide(&query(name, RecordType::A), &rules, true), Decision::Forward), "{name}");
    }
}

#[test]
fn firefox_doh_canary_is_nxdomain() {
    let rules = blocked(&[], &[]);
    let reply = answer(dns::decide(&query("use-application-dns.net.", RecordType::A), &rules, true));
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
}

#[test]
fn malformed_and_unsupported_messages_never_forward() {
    let rules = blocked(&["example.com"], &[]);
    assert!(matches!(dns::decide(b"\x00\x01garbage", &rules, true), Decision::Drop));
    assert!(matches!(dns::decide(&[], &rules, true), Decision::Drop));
    let mut response = Message::from_vec(&query("example.org.", RecordType::A)).unwrap();
    response.metadata.message_type = MessageType::Response;
    assert!(matches!(dns::decide(&response.to_vec().unwrap(), &rules, true), Decision::Drop));
    let mut update = Message::new(7, MessageType::Query, OpCode::Update);
    update.add_query(Query::query(Name::from_ascii("example.org.").unwrap(), RecordType::A));
    assert_eq!(answer(dns::decide(&update.to_vec().unwrap(), &rules, true)).metadata.response_code, ResponseCode::NotImp);
    let mut double = Message::from_vec(&query("example.org.", RecordType::A)).unwrap();
    double.add_query(Query::query(Name::from_ascii("example.com.").unwrap(), RecordType::A));
    assert_eq!(answer(dns::decide(&double.to_vec().unwrap(), &rules, true)).metadata.response_code, ResponseCode::FormErr);
}

/// Fake upstream answering every query with UPSTREAM_IP; optionally sends a spoofed reply first.
fn fake_upstream(spoof_first: bool, silent: bool) -> (SocketAddr, Arc<StopSignal>, std::thread::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    let address = socket.local_addr().unwrap();
    let stop = Arc::new(StopSignal::default());
    let worker_stop = Arc::clone(&stop);
    let worker = std::thread::spawn(move || {
        let impostor = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut buffer = [0u8; 4096];
        while !worker_stop.is_stopped() {
            let Ok((length, peer)) = socket.recv_from(&mut buffer) else { continue };
            if silent {
                continue;
            }
            let request = Message::from_vec(&buffer[..length]).unwrap();
            let mut reply = Message::response(request.metadata.id, OpCode::Query);
            reply.add_queries(request.queries.clone());
            let name = request.queries[0].name().clone();
            reply.add_answer(Record::from_rdata(name, 300, RData::A(A(UPSTREAM_IP))));
            if spoof_first {
                let mut forged = reply.clone();
                forged.metadata.id = request.metadata.id.wrapping_add(1);
                forged.answers.clear();
                forged.add_answer(Record::from_rdata(request.queries[0].name().clone(), 300, RData::A(A(Ipv4Addr::new(6, 6, 6, 6)))));
                socket.send_to(&forged.to_vec().unwrap(), peer).unwrap();
                impostor.send_to(&forged.to_vec().unwrap(), peer).unwrap();
            }
            socket.send_to(&reply.to_vec().unwrap(), peer).unwrap();
        }
    });
    (address, stop, worker)
}

fn start_resolver(rules: Arc<BlockedDomains>, upstream: SocketAddr) -> (SocketAddr, Arc<StopSignal>, std::thread::JoinHandle<()>) {
    let stop = Arc::new(StopSignal::default());
    let upstreams = Arc::new(StaticUpstreams(vec![upstream]));
    let (bound, worker) =
        dns::start(&["127.0.0.1:0".parse().unwrap()], rules, true, upstreams, Arc::clone(&stop)).unwrap();
    (bound[0], stop, worker)
}

fn udp_exchange(server: SocketAddr, bytes: &[u8], timeout: Duration) -> Option<Message> {
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.set_read_timeout(Some(timeout)).unwrap();
    client.send_to(bytes, server).unwrap();
    let mut buffer = [0u8; 4096];
    let (length, _) = client.recv_from(&mut buffer).ok()?;
    Some(Message::from_vec(&buffer[..length]).unwrap())
}

#[test]
fn udp_server_answers_blocked_and_forwards_allowed_ignoring_spoofed_replies() {
    let (upstream, upstream_stop, upstream_worker) = fake_upstream(true, false);
    let (server, stop, worker) = start_resolver(blocked(&["*.example.com"], &[]), upstream);
    let local = udp_exchange(server, &query("x.example.com.", RecordType::A), Duration::from_secs(3)).unwrap();
    assert_eq!(addresses(&local), vec!["127.0.0.1"]);
    let request = query("example.org.", RecordType::A);
    let forwarded = udp_exchange(server, &request, Duration::from_secs(3)).unwrap();
    assert_eq!(forwarded.metadata.id, Message::from_vec(&request).unwrap().metadata.id);
    assert_eq!(addresses(&forwarded), vec![UPSTREAM_IP.to_string()]);
    // Garbage must not stop the worker.
    UdpSocket::bind("127.0.0.1:0").unwrap().send_to(b"\xff\xff\xff", server).unwrap();
    assert!(udp_exchange(server, &query("x.example.com.", RecordType::A), Duration::from_secs(3)).is_some());
    stop.stop();
    worker.join().unwrap();
    upstream_stop.stop();
    upstream_worker.join().unwrap();
}

#[test]
fn silent_upstream_yields_servfail_within_deadline() {
    let (upstream, upstream_stop, upstream_worker) = fake_upstream(false, true);
    let (server, stop, worker) = start_resolver(blocked(&[], &[]), upstream);
    let started = Instant::now();
    let reply = udp_exchange(server, &query("example.org.", RecordType::A), Duration::from_secs(5)).unwrap();
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert!(started.elapsed() < Duration::from_secs(4));
    stop.stop();
    worker.join().unwrap();
    upstream_stop.stop();
    upstream_worker.join().unwrap();
}

#[test]
fn tcp_queries_are_answered_and_forwarded() {
    let (upstream, upstream_stop, upstream_worker) = fake_upstream(false, false);
    let (server, stop, worker) = start_resolver(blocked(&["example.com"], &[]), upstream);
    for (name, expected) in [("example.com.", "127.0.0.1".to_owned()), ("example.org.", UPSTREAM_IP.to_string())] {
        let mut stream = TcpStream::connect(server).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let bytes = query(name, RecordType::A);
        stream.write_all(&(bytes.len() as u16).to_be_bytes()).unwrap();
        stream.write_all(&bytes).unwrap();
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).unwrap();
        let mut reply = vec![0u8; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(addresses(&Message::from_vec(&reply).unwrap()), vec![expected], "{name}");
    }
    stop.stop();
    worker.join().unwrap();
    upstream_stop.stop();
    upstream_worker.join().unwrap();
    assert!(TcpStream::connect(server).is_err());
}

#[test]
fn port_conflict_fails_before_serving() {
    let taken = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = taken.local_addr().unwrap();
    let stop = Arc::new(StopSignal::default());
    let upstreams = Arc::new(StaticUpstreams(vec![]));
    assert!(dns::start(&[address], blocked(&[], &[]), true, upstreams, stop).is_err());
}

#[test]
fn ipv6_loopback_answers_when_available() {
    let Ok(probe) = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)) else { return };
    drop(probe);
    let stop = Arc::new(StopSignal::default());
    let (bound, worker) = dns::start(
        &["[::1]:0".parse().unwrap()],
        blocked(&["example.com"], &[]),
        true,
        Arc::new(StaticUpstreams(vec![])),
        Arc::clone(&stop),
    )
    .unwrap();
    let client = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    client.send_to(&query("example.com.", RecordType::AAAA), bound[0]).unwrap();
    let mut buffer = [0u8; 512];
    let (length, _) = client.recv_from(&mut buffer).unwrap();
    assert_eq!(addresses(&Message::from_vec(&buffer[..length]).unwrap()), vec!["::1"]);
    stop.stop();
    worker.join().unwrap();
}
