//! Loopback DNS resolver. Blocked names get local answers; every other query is forwarded
//! unchanged to the network adapters' resolvers. No cache: the Windows DNS client keeps one.
use crate::error::Result;
use crate::https_blockpage::BlockedDomains;
use crate::runtime::StopSignal;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const BLOCKED_TTL: u32 = 30;
const MAX_MESSAGE: usize = 4096;
const SERVER_TIMEOUT: Duration = Duration::from_secs(2);
const QUERY_BUDGET: Duration = Duration::from_secs(3);
const MAX_IN_FLIGHT: usize = 128;
const MAX_TCP_CONNECTIONS: usize = 32;
const MAX_TCP_QUERIES: usize = 16;
/// Standard signal that makes Firefox turn off automatic DNS over HTTPS.
const DOH_CANARY: &str = "use-application-dns.net";

#[derive(Debug)]
pub enum Decision {
    Answer(Vec<u8>),
    Forward,
    Drop,
}

/// Where allowed queries go. Production reads the adapters on every query.
pub trait Upstreams: Send + Sync {
    fn servers(&self) -> Vec<SocketAddr>;
}

pub struct StaticUpstreams(pub Vec<SocketAddr>);

impl Upstreams for StaticUpstreams {
    fn servers(&self) -> Vec<SocketAddr> {
        self.0.clone()
    }
}

fn encode(message: Message) -> Decision {
    message.to_vec().map_or(Decision::Drop, Decision::Answer)
}

fn reply(request: &Message, code: ResponseCode) -> Message {
    let mut message = Message::error_msg(request.metadata.id, request.metadata.op_code, code);
    message.metadata.recursion_desired = request.metadata.recursion_desired;
    message.metadata.recursion_available = true;
    message.add_queries(request.queries.clone());
    message
}

/// Local decision for one query; malformed input is dropped and never forwarded.
pub fn decide(bytes: &[u8], blocked: &BlockedDomains, redirect: bool) -> Decision {
    let Ok(request) = Message::from_vec(bytes) else { return Decision::Drop };
    if request.metadata.message_type != MessageType::Query {
        return Decision::Drop;
    }
    if request.metadata.op_code != OpCode::Query {
        return encode(reply(&request, ResponseCode::NotImp));
    }
    let [question] = request.queries.as_slice() else {
        return encode(reply(&request, ResponseCode::FormErr));
    };
    let name = question.name().to_ascii().trim_end_matches('.').to_ascii_lowercase();
    if name == DOH_CANARY {
        return encode(reply(&request, ResponseCode::NXDomain));
    }
    if !blocked.contains(&name) {
        return Decision::Forward;
    }
    let mut message = reply(&request, ResponseCode::NoError);
    let data = match question.query_type() {
        RecordType::A => Some(RData::A(A(if redirect { Ipv4Addr::LOCALHOST } else { Ipv4Addr::UNSPECIFIED }))),
        RecordType::AAAA => Some(RData::AAAA(AAAA(if redirect { Ipv6Addr::LOCALHOST } else { Ipv6Addr::UNSPECIFIED }))),
        // HTTPS/SVCB and every other type: NODATA, so browsers fall back to the redirected A/AAAA.
        _ => None,
    };
    if let Some(data) = data {
        message.add_answer(Record::from_rdata(question.name().clone(), BLOCKED_TTL, data));
    }
    encode(message)
}

fn servfail(bytes: &[u8]) -> Option<Vec<u8>> {
    let request = Message::from_vec(bytes).ok()?;
    reply(&request, ResponseCode::ServFail).to_vec().ok()
}

/// A reply counts only if it parses, matches the ID and echoes the same question.
fn matches_request(request: &Message, reply: &[u8]) -> bool {
    Message::from_vec(reply).is_ok_and(|message| {
        message.metadata.message_type == MessageType::Response
            && message.metadata.id == request.metadata.id
            && message.queries == request.queries
    })
}

fn usable(server: &SocketAddr, own: &[SocketAddr]) -> bool {
    !own.contains(server) && !(server.ip().is_loopback() && server.port() == 53) && !server.ip().is_unspecified()
}

fn forward_udp(bytes: &[u8], servers: &[SocketAddr], own: &[SocketAddr]) -> Option<Vec<u8>> {
    let request = Message::from_vec(bytes).ok()?;
    let budget = Instant::now() + QUERY_BUDGET;
    for server in servers.iter().filter(|server| usable(server, own)) {
        let local: SocketAddr = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().ok()?;
        let Ok(socket) = UdpSocket::bind(local) else { continue };
        // A connected socket only receives datagrams from this server's address and port.
        if socket.connect(server).is_err() || socket.send(bytes).is_err() {
            continue;
        }
        let deadline = budget.min(Instant::now() + SERVER_TIMEOUT);
        let mut buffer = [0u8; MAX_MESSAGE];
        while let Some(remaining) = deadline.checked_duration_since(Instant::now()).filter(|left| !left.is_zero()) {
            if socket.set_read_timeout(Some(remaining)).is_err() {
                break;
            }
            match socket.recv(&mut buffer) {
                Ok(length) if matches_request(&request, &buffer[..length]) => return Some(buffer[..length].to_vec()),
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        if Instant::now() >= budget {
            break;
        }
    }
    None
}

fn read_frame(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).ok()?;
    let length = u16::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_MESSAGE {
        return None;
    }
    let mut message = vec![0u8; length];
    stream.read_exact(&mut message).ok()?;
    Some(message)
}

fn write_frame(stream: &mut TcpStream, message: &[u8]) -> std::io::Result<()> {
    let length = u16::try_from(message.len()).map_err(std::io::Error::other)?;
    stream.write_all(&[&length.to_be_bytes()[..], message].concat())
}

fn truncated(reply: &[u8]) -> bool {
    reply.get(2).is_some_and(|flags| flags & 0x02 != 0)
}

fn forward_tcp(bytes: &[u8], servers: &[SocketAddr], own: &[SocketAddr]) -> Option<Vec<u8>> {
    let request = Message::from_vec(bytes).ok()?;
    for server in servers.iter().filter(|server| usable(server, own)) {
        let Ok(mut stream) = TcpStream::connect_timeout(server, SERVER_TIMEOUT) else { continue };
        let _ = stream.set_read_timeout(Some(SERVER_TIMEOUT));
        let _ = stream.set_write_timeout(Some(SERVER_TIMEOUT));
        if write_frame(&mut stream, bytes).is_err() {
            continue;
        }
        if let Some(reply) = read_frame(&mut stream).filter(|reply| matches_request(&request, reply)) {
            return Some(reply);
        }
    }
    None
}

/// Decrements the shared counter when a worker finishes, even on panic.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(counter: &Arc<AtomicUsize>, limit: usize) -> Option<Slot> {
        let previous = counter.fetch_add(1, Ordering::AcqRel);
        if previous >= limit {
            counter.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(Slot(Arc::clone(counter)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Shared {
    blocked: Arc<BlockedDomains>,
    redirect: bool,
    upstreams: Arc<dyn Upstreams>,
    own: Vec<SocketAddr>,
    in_flight: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
}

fn serve_udp(socket: &UdpSocket, shared: &Arc<Shared>, stop: &StopSignal) {
    let mut buffer = [0u8; MAX_MESSAGE];
    while !stop.is_stopped() {
        // Errors include timeouts and Windows ICMP resets from departed clients; keep serving.
        let Ok((length, peer)) = socket.recv_from(&mut buffer) else { continue };
        let query = buffer[..length].to_vec();
        match decide(&query, &shared.blocked, shared.redirect) {
            Decision::Answer(bytes) => {
                let _ = socket.send_to(&bytes, peer);
            }
            Decision::Drop => {}
            Decision::Forward => {
                let Some(slot) = Slot::take(&shared.in_flight, MAX_IN_FLIGHT) else { continue };
                let (Ok(sender), shared) = (socket.try_clone(), Arc::clone(shared)) else { continue };
                let _ = std::thread::Builder::new().name("openems-dns-forward".into()).spawn(move || {
                    let _slot = slot;
                    let mut reply = forward_udp(&query, &shared.upstreams.servers(), &shared.own);
                    if reply.is_none() {
                        reply = servfail(&query);
                    }
                    if let Some(reply) = reply {
                        let _ = sender.send_to(&reply, peer);
                    }
                });
            }
        }
    }
}

fn serve_tcp_connection(mut stream: TcpStream, shared: &Shared) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    for _ in 0..MAX_TCP_QUERIES {
        let Some(query) = read_frame(&mut stream) else { return };
        let reply = match decide(&query, &shared.blocked, shared.redirect) {
            Decision::Answer(bytes) => Some(bytes),
            Decision::Drop => return,
            Decision::Forward => {
                let servers = shared.upstreams.servers();
                let mut reply = forward_udp(&query, &servers, &shared.own);
                if reply.as_deref().is_some_and(truncated) {
                    reply = forward_tcp(&query, &servers, &shared.own).or(reply);
                }
                reply.or_else(|| servfail(&query))
            }
        };
        match reply {
            Some(reply) if write_frame(&mut stream, &reply).is_ok() => {}
            _ => return,
        }
    }
}

fn serve_tcp(listener: &TcpListener, shared: &Arc<Shared>, stop: &StopSignal) {
    while !stop.is_stopped() {
        match listener.accept() {
            Ok((stream, _)) => {
                let Some(slot) = Slot::take(&shared.connections, MAX_TCP_CONNECTIONS) else { continue };
                let shared = Arc::clone(shared);
                let _ = std::thread::Builder::new().name("openems-dns-tcp".into()).spawn(move || {
                    let _slot = slot;
                    serve_tcp_connection(stream, &shared);
                });
            }
            Err(_) => {
                stop.wait(Duration::from_millis(50));
            }
        }
    }
}

/// Bind UDP and TCP on every address synchronously; callers must not redirect DNS if this fails.
pub fn start(
    addresses: &[SocketAddr],
    blocked: Arc<BlockedDomains>,
    redirect: bool,
    upstreams: Arc<dyn Upstreams>,
    stop: Arc<StopSignal>,
) -> Result<(Vec<SocketAddr>, JoinHandle<()>)> {
    let mut sockets = Vec::new();
    let mut listeners = Vec::new();
    for address in addresses {
        let socket = UdpSocket::bind(address)?;
        let bound = socket.local_addr()?;
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;
        let listener = TcpListener::bind(bound)?;
        listener.set_nonblocking(true)?;
        sockets.push(socket);
        listeners.push(listener);
    }
    let own: Vec<SocketAddr> = sockets.iter().map(UdpSocket::local_addr).collect::<std::io::Result<_>>()?;
    let shared = Arc::new(Shared {
        blocked,
        redirect,
        upstreams,
        own: own.clone(),
        in_flight: Arc::new(AtomicUsize::new(0)),
        connections: Arc::new(AtomicUsize::new(0)),
    });
    let worker = std::thread::Builder::new().name("openems-dns".into()).spawn(move || {
        std::thread::scope(|scope| {
            for socket in &sockets {
                let (shared, stop) = (&shared, &stop);
                scope.spawn(move || serve_udp(socket, shared, stop));
            }
            for listener in &listeners {
                let (shared, stop) = (&shared, &stop);
                scope.spawn(move || serve_tcp(listener, shared, stop));
            }
        });
    })?;
    Ok((own, worker))
}
