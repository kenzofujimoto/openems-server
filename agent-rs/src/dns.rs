//! Loopback DNS resolver. Blocked names get local answers; every other query is forwarded
//! unchanged to the network adapters' resolvers. No cache: the Windows DNS client keeps one.
use crate::error::Result;
use crate::https_blockpage::BlockedDomains;
use crate::runtime::StopSignal;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const BLOCKED_TTL: u32 = 30;
const SAFE_SEARCH_TTL: u32 = 300;
const MAX_MESSAGE: usize = 4096;
const SERVER_TIMEOUT: Duration = Duration::from_secs(2);
const QUERY_BUDGET: Duration = Duration::from_secs(3);
const MAX_IN_FLIGHT: usize = 128;
const MAX_TCP_CONNECTIONS: usize = 32;
const MAX_TCP_QUERIES: usize = 16;
/// Adapter servers are re-read at most this often; network changes apply within it.
const UPSTREAM_REFRESH: Duration = Duration::from_secs(5);
/// Standard signal that makes Firefox turn off automatic DNS over HTTPS.
const DOH_CANARY: &str = "use-application-dns.net";

#[derive(Debug)]
pub enum Decision {
    Answer(Vec<u8>),
    Forward,
    /// Answer with a CNAME to this enforced SafeSearch host plus its upstream addresses.
    SafeSearch(&'static str),
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

/// Keep order; drop loopback, unspecified, multicast, the deprecated fec0::/10 defaults
/// and link-local IPv6 servers without a scope.
fn filter_upstreams(candidates: Vec<(IpAddr, u32)>) -> Vec<SocketAddr> {
    let mut servers: Vec<SocketAddr> = Vec::new();
    for (ip, scope) in candidates {
        let server = match ip {
            IpAddr::V4(v4) if !(v4.is_loopback() || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast()) => {
                SocketAddr::from((v4, 53))
            }
            IpAddr::V6(v6) => {
                let prefix = v6.segments()[0] & 0xffc0;
                let link_local = prefix == 0xfe80;
                if v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || prefix == 0xfec0
                    || (link_local && scope == 0)
                {
                    continue;
                }
                SocketAddr::V6(SocketAddrV6::new(v6, 53, 0, if link_local { scope } else { 0 }))
            }
            IpAddr::V4(_) => continue,
        };
        if !servers.contains(&server) {
            servers.push(server);
        }
    }
    servers
}

/// DNS servers of the active network adapters, which the NRPT rule leaves untouched.
#[derive(Default)]
pub struct AdapterUpstreams {
    cache: Mutex<Option<(Instant, Vec<SocketAddr>)>>,
}

impl Upstreams for AdapterUpstreams {
    fn servers(&self) -> Vec<SocketAddr> {
        let mut cache = self.cache.lock().unwrap_or_else(|poison| poison.into_inner());
        if let Some((read, servers)) = cache.as_ref()
            && read.elapsed() < UPSTREAM_REFRESH
        {
            return servers.clone();
        }
        // A failed read keeps the previous list instead of failing every allowed query.
        let servers = adapter_dns_servers()
            .unwrap_or_else(|_| cache.as_ref().map(|(_, servers)| servers.clone()).unwrap_or_default());
        *cache = Some((Instant::now(), servers.clone()));
        servers
    }
}

#[cfg(windows)]
fn adapter_dns_servers() -> Result<Vec<SocketAddr>> {
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_FRIENDLY_NAME, GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST,
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_DNS_SERVER_ADDRESS_XP,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6};
    let flags = GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_FRIENDLY_NAME;
    let mut size: u32 = 16 * 1024;
    for _ in 0..4 {
        // u64 storage keeps the adapter structures aligned.
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        let first = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: `size` describes `buffer`; the API writes a linked list inside it.
        let status = unsafe { GetAdaptersAddresses(u32::from(AF_UNSPEC), flags, std::ptr::null(), first, &mut size) };
        if status == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if status != NO_ERROR {
            return Err(crate::error::AgentError::Local("cannot read adapter DNS servers".into()));
        }
        let mut candidates = Vec::new();
        let mut adapter = first.cast_const();
        // SAFETY: every pointer comes from the list written into `buffer`, alive in this scope.
        unsafe {
            while !adapter.is_null() {
                if (*adapter).OperStatus == IfOperStatusUp {
                    let mut server = (*adapter).FirstDnsServerAddress.cast_const();
                    while !server.is_null() {
                        let address = (*server).Address.lpSockaddr;
                        if !address.is_null() {
                            match (*address).sa_family {
                                AF_INET => {
                                    let v4 = &*address.cast::<SOCKADDR_IN>();
                                    candidates.push((IpAddr::from(v4.sin_addr.S_un.S_addr.to_ne_bytes()), 0));
                                }
                                AF_INET6 => {
                                    let v6 = &*address.cast::<SOCKADDR_IN6>();
                                    candidates.push((IpAddr::from(v6.sin6_addr.u.Byte), v6.Anonymous.sin6_scope_id));
                                }
                                _ => {}
                            }
                        }
                        server = (*server).Next.cast_const() as *const IP_ADAPTER_DNS_SERVER_ADDRESS_XP;
                    }
                }
                adapter = (*adapter).Next.cast_const();
            }
        }
        return Ok(filter_upstreams(candidates));
    }
    Err(crate::error::AgentError::Local("adapter list keeps growing; retry later".into()))
}

#[cfg(not(windows))]
fn adapter_dns_servers() -> Result<Vec<SocketAddr>> {
    let text = std::fs::read_to_string("/etc/resolv.conf")?;
    let candidates = text
        .lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver"))
        .filter_map(|value| value.trim().parse::<IpAddr>().ok())
        .map(|ip| (ip, 0))
        .collect();
    Ok(filter_upstreams(candidates))
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
    if name == DOH_CANARY || blocked.blocks_doh(&name) {
        return encode(reply(&request, ResponseCode::NXDomain));
    }
    if !blocked.contains(&name) {
        // Allowed engines keep SafeSearch: "allowed" means not blocked, not unfiltered.
        return match blocked.safe_search_target(&name) {
            Some(target) if matches!(question.query_type(), RecordType::A | RecordType::AAAA) => {
                Decision::SafeSearch(target)
            }
            Some(_) => encode(reply(&request, ResponseCode::NoError)),
            None => Decision::Forward,
        };
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

fn forward(bytes: &[u8], servers: &[SocketAddr], own: &[SocketAddr]) -> Option<Vec<u8>> {
    let reply = forward_udp(bytes, servers, own);
    if reply.as_deref().is_some_and(truncated) {
        return forward_tcp(bytes, servers, own).or(reply);
    }
    reply
}

/// CNAME to the SafeSearch host plus its upstream records. The engine's own name is never
/// forwarded; any upstream failure yields None, which callers turn into SERVFAIL.
fn safe_search_reply(bytes: &[u8], target: &str, servers: &[SocketAddr], own: &[SocketAddr]) -> Option<Vec<u8>> {
    let request = Message::from_vec(bytes).ok()?;
    let question = request.queries.first()?;
    let target_name = Name::from_ascii(format!("{target}.")).ok()?;
    let mut lookup = Message::query();
    lookup.metadata.recursion_desired = true;
    lookup.add_query(Query::query(target_name.clone(), question.query_type()));
    let upstream = Message::from_vec(&forward(&lookup.to_vec().ok()?, servers, own)?).ok()?;
    if upstream.metadata.response_code != ResponseCode::NoError {
        return None;
    }
    let mut message = reply(&request, ResponseCode::NoError);
    message.add_answer(Record::from_rdata(question.name().clone(), SAFE_SEARCH_TTL, RData::CNAME(CNAME(target_name))));
    message.add_answers(upstream.answers);
    message.to_vec().ok()
}

/// Reply for a query that leaves this machine: forwarded unchanged, or rewritten for SafeSearch.
fn remote_reply(query: &[u8], target: Option<&str>, shared: &Shared) -> Option<Vec<u8>> {
    let servers = shared.upstreams.servers();
    let reply = match target {
        Some(target) => safe_search_reply(query, target, &servers, &shared.own),
        None => forward(query, &servers, &shared.own),
    };
    reply.or_else(|| servfail(query))
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
            decision @ (Decision::Forward | Decision::SafeSearch(_)) => {
                let target = if let Decision::SafeSearch(target) = decision { Some(target) } else { None };
                let Some(slot) = Slot::take(&shared.in_flight, MAX_IN_FLIGHT) else { continue };
                let (Ok(sender), shared) = (socket.try_clone(), Arc::clone(shared)) else { continue };
                let _ = std::thread::Builder::new().name("openems-dns-forward".into()).spawn(move || {
                    let _slot = slot;
                    if let Some(reply) = remote_reply(&query, target, &shared) {
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
            Decision::Forward => remote_reply(&query, None, shared),
            Decision::SafeSearch(target) => remote_reply(&query, Some(target), shared),
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

/// UDP and TCP on one port. For port 0, retry: Windows may reserve a free UDP port for TCP
/// (Hyper-V and WinNAT exclusion ranges), which fails the TCP bind with WSAEACCES.
fn bind_pair(address: SocketAddr) -> std::io::Result<(UdpSocket, TcpListener)> {
    let attempts = if address.port() == 0 { 32 } else { 1 };
    let mut last = None;
    for _ in 0..attempts {
        let socket = UdpSocket::bind(address)?;
        match TcpListener::bind(socket.local_addr()?) {
            Ok(listener) => return Ok((socket, listener)),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("no port available for UDP and TCP")))
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
        let (socket, listener) = bind_pair(*address)?;
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, SocketAddrV6};

    #[test]
    fn upstream_candidates_skip_loopback_placeholders_and_duplicates() {
        let candidates: Vec<(IpAddr, u32)> = vec![
            ("192.168.1.1".parse().unwrap(), 0),
            ("127.0.0.1".parse().unwrap(), 0),
            ("::1".parse().unwrap(), 0),
            ("0.0.0.0".parse().unwrap(), 0),
            ("fec0:0:0:ffff::1".parse().unwrap(), 0),
            ("224.0.0.251".parse().unwrap(), 0),
            ("192.168.1.1".parse().unwrap(), 0),
            ("2001:4860:4860::8888".parse().unwrap(), 0),
            ("fe80::1".parse().unwrap(), 7),
            ("fe80::2".parse().unwrap(), 0),
        ];
        assert_eq!(
            filter_upstreams(candidates),
            vec![
                "192.168.1.1:53".parse::<SocketAddr>().unwrap(),
                "[2001:4860:4860::8888]:53".parse().unwrap(),
                SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 53, 0, 7)),
            ]
        );
    }

    #[cfg(windows)]
    #[test]
    fn adapter_discovery_reads_without_changing_anything() {
        let servers = AdapterUpstreams::default().servers();
        assert!(servers.iter().all(|server| !server.ip().is_loopback() && server.port() == 53));
    }
}
