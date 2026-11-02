//! Loopback TLS responder. It never forwards traffic and signs only active blocked names.
use crate::authority::Authority;
use crate::error::{AgentError, Result};
use crate::policy::{WebFilter, normalize_domain};
use crate::runtime::StopSignal;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Active web filter for SNI and Host authorization; shared with DNS answers.
/// Scheduled windows are evaluated at each lookup, so no timer is needed to apply them.
#[derive(Default)]
pub struct BlockedDomains {
    filter: RwLock<WebFilter>,
    /// Downloaded category sets the filter consults for blocked_categories.
    categories: crate::categories::CategoryStore,
    /// Anti-bypass: public DoH endpoint names get NXDOMAIN from the resolver.
    block_doh: AtomicBool,
    /// Blocked DNS answers since the last upload.
    log: crate::events::BlockLog,
    /// Warnings the person chose to continue past: category or domain key until its expiry.
    proceeded: Mutex<HashMap<String, Instant>>,
    /// Single-use tokens of warning pages: token → (host, expiry).
    tokens: Mutex<HashMap<String, (String, Instant)>>,
}

/// How long a "continue" on a warning page lasts, and how long its form stays valid.
pub const WARN_GRACE: Duration = Duration::from_secs(60 * 60);
const TOKEN_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// Bounds per-machine memory: warnings are human clicks, so these are generous.
const MAX_PROCEEDED: usize = 512;
const MAX_TOKENS: usize = 256;

/// A warning is acknowledged per category, or per domain when a domain rule warns.
fn warning_key(name: &str, decision: &crate::policy::WebDecision) -> Option<String> {
    match &decision.reason {
        Some(crate::policy::BlockReason::Category(id)) => Some(format!("category:{id}")),
        Some(crate::policy::BlockReason::Rule) => normalize_domain(name).ok().map(|domain| format!("domain:{domain}")),
        None => None,
    }
}

fn prune<T>(map: &mut HashMap<String, T>, expiry: impl Fn(&T) -> Instant, limit: usize) {
    let now = Instant::now();
    map.retain(|_, value| expiry(value) > now);
    while map.len() >= limit {
        let Some(oldest) = map.iter().min_by_key(|(_, value)| expiry(value)).map(|(key, _)| key.clone()) else { break };
        map.remove(&oldest);
    }
}

impl BlockedDomains {
    pub fn replace(&self, filter: impl Into<WebFilter>) {
        // A poisoned lock still holds a consistent snapshot; the writer only swaps whole values.
        *self.filter.write().unwrap_or_else(|poison| poison.into_inner()) = filter.into();
    }

    pub fn contains(&self, name: &str) -> bool {
        self.contains_at(name, jiff::Timestamp::now())
    }

    /// Names the agent answers locally: blocked ones and warnings not yet continued past.
    pub fn contains_at(&self, name: &str, when: jiff::Timestamp) -> bool {
        let filter = self.filter.read().unwrap_or_else(|poison| poison.into_inner());
        filter.blocks_at_with(name, when, &self.categories) || {
            let decision = filter.decision_at(name, when, &self.categories);
            decision.action == crate::policy::WebAction::Warn && !self.continued(name, &decision)
        }
    }

    fn continued(&self, name: &str, decision: &crate::policy::WebDecision) -> bool {
        let Some(key) = warning_key(name, decision) else { return false };
        let proceeded = self.proceeded.lock().unwrap_or_else(|poison| poison.into_inner());
        proceeded.get(&key).is_some_and(|expiry| *expiry > Instant::now())
    }

    /// The name currently shows a warning page (not blocked, not continued past).
    pub fn warns(&self, name: &str) -> bool {
        self.decision(name).action == crate::policy::WebAction::Warn
    }

    /// A fresh single-use token for the warning page of `name`.
    pub fn issue_token(&self, name: &str) -> String {
        let mut bytes = [0u8; 32];
        // The token only binds a form to the page that showed it; a failed RNG yields an unusable token.
        if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes).is_err() {
            return String::new();
        }
        let token = hex::encode(bytes);
        let mut tokens = self.tokens.lock().unwrap_or_else(|poison| poison.into_inner());
        prune(&mut tokens, |(_, expiry)| *expiry, MAX_TOKENS);
        tokens.insert(token.clone(), (name.to_ascii_lowercase(), Instant::now() + TOKEN_LIFETIME));
        token
    }

    /// Continue past the warning of `name`; only a live token issued for that name and a current warning count.
    pub fn proceed(&self, name: &str, token: &str) -> bool {
        let issued = self.tokens.lock().unwrap_or_else(|poison| poison.into_inner()).remove(token);
        let Some((host, expiry)) = issued else { return false };
        if host != name.to_ascii_lowercase() || expiry <= Instant::now() {
            return false;
        }
        let decision = self.decision(name);
        let Some(key) = warning_key(name, &decision).filter(|_| decision.action == crate::policy::WebAction::Warn)
        else {
            return false;
        };
        let mut proceeded = self.proceeded.lock().unwrap_or_else(|poison| poison.into_inner());
        prune(&mut proceeded, |expiry| *expiry, MAX_PROCEEDED);
        proceeded.insert(key, Instant::now() + WARN_GRACE);
        true
    }

    pub fn reason(&self, name: &str) -> Option<crate::policy::BlockReason> {
        self.filter.read().unwrap_or_else(|poison| poison.into_inner()).block_reason_at(
            name,
            jiff::Timestamp::now(),
            &self.categories,
        )
    }

    /// The policy decision, where a warning already continued past is monitored instead.
    pub fn decision(&self, name: &str) -> crate::policy::WebDecision {
        let decision = self.filter.read().unwrap_or_else(|poison| poison.into_inner()).decision_at(
            name,
            jiff::Timestamp::now(),
            &self.categories,
        );
        if decision.action == crate::policy::WebAction::Warn && self.continued(name, &decision) {
            return crate::policy::WebDecision { action: crate::policy::WebAction::Monitor, ..decision };
        }
        decision
    }

    /// Display name of the category blocking or warning about `name`; None for rules and other names.
    pub fn category_label(&self, name: &str) -> Option<&'static str> {
        let reason = self.reason(name).or_else(|| self.decision(name).reason)?;
        match reason {
            crate::policy::BlockReason::Category(id) => crate::policy::category_label(&id),
            crate::policy::BlockReason::Rule => None,
        }
    }

    pub fn block_log(&self) -> &crate::events::BlockLog {
        &self.log
    }

    pub fn safe_search_target(&self, name: &str) -> Option<&'static str> {
        self.filter.read().unwrap_or_else(|poison| poison.into_inner()).safe_search_target(name)
    }

    pub fn categories(&self) -> &crate::categories::CategoryStore {
        &self.categories
    }

    /// Categories the active policy can use, for downloading and pruning.
    pub fn referenced_categories(&self) -> Vec<String> {
        self.filter.read().unwrap_or_else(|poison| poison.into_inner()).referenced_categories()
    }

    pub fn set_doh_blocking(&self, enabled: bool) {
        self.block_doh.store(enabled, Ordering::Relaxed);
    }

    pub fn blocks_doh(&self, name: &str) -> bool {
        self.block_doh.load(Ordering::Relaxed) && crate::doh::is_doh_host(name)
    }
}

struct Resolver {
    authority: Mutex<Authority>,
    allowed: Arc<BlockedDomains>,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlockedDomainResolver")
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name()?;
        // No leaf cache: signing is bounded by the four connection workers.
        if !self.allowed.contains(name) {
            return None;
        }
        self.authority.lock().ok()?.issue(name).ok()
    }
}

fn request_host(request: &str) -> Option<String> {
    let mut lines = request.split("\r\n");
    let first: Vec<_> = lines.next()?.split(' ').collect();
    let method = first.first().copied();
    if first.len() != 3
        || !matches!(method, Some("GET" | "POST"))
        || !first[1].starts_with('/')
        || first[2] != "HTTP/1.1"
    {
        return None;
    }
    let mut host = None;
    for line in lines.take_while(|line| !line.is_empty()) {
        let (key, value) = line.split_once(':')?;
        if key.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return None;
            }
            let value = value.trim();
            let name = match value.split_once(':') {
                Some((name, port)) if !port.is_empty() && port.parse::<u16>().is_ok() => name,
                Some(_) => return None,
                None => value,
            };
            host = Some(normalize_domain(name).ok()?);
        }
    }
    host
}

struct DeadlineSocket {
    socket: TcpStream,
    deadline: Instant,
}

impl Read for DeadlineSocket {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS request deadline"))?;
        self.socket.set_read_timeout(Some(remaining.min(Duration::from_millis(500))))?;
        self.socket.read(buffer)
    }
}

impl Write for DeadlineSocket {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS request deadline"));
        }
        self.socket.write(buffer)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.socket.flush()
    }
}

fn serve(socket: TcpStream, config: Arc<rustls::ServerConfig>, allowed: &BlockedDomains) -> std::io::Result<()> {
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_millis(500)))?;
    socket.set_write_timeout(Some(Duration::from_millis(500)))?;
    let connection = rustls::ServerConnection::new(config).map_err(std::io::Error::other)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stream = rustls::StreamOwned::new(connection, DeadlineSocket { socket, deadline });
    let mut request = Vec::new();
    let mut buffer = [0u8; 1024];
    while request.len() < 8192 && Instant::now() < deadline {
        let length = stream.read(&mut buffer)?;
        if length == 0 {
            return Ok(());
        }
        request.extend_from_slice(&buffer[..length]);
        if request.windows(4).any(|part| part == b"\r\n\r\n") {
            break;
        }
    }
    let name = stream.conn.server_name().unwrap_or_default();
    let valid = request.len() <= 8192
        && request.ends_with(b"\r\n\r\n")
        && std::str::from_utf8(&request).ok().and_then(request_host).as_deref() == Some(name)
        && allowed.contains(name);
    let (status, body) = if valid {
        ("200 OK", crate::blockpage::respond(&String::from_utf8_lossy(&request), name, allowed))
    } else {
        ("421 Misdirected Request", String::new())
    };
    stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())?;
    stream.conn.send_close_notify();
    stream.flush()
}

/// Bind synchronously; caller must not enforce redirects if startup fails.
pub fn start(
    port: u16,
    authority: Authority,
    allowed: Arc<BlockedDomains>,
    stop: Arc<StopSignal>,
) -> Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let address = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let resolver = Arc::new(Resolver { authority: Mutex::new(authority), allowed: Arc::clone(&allowed) });
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| AgentError::Local(error.to_string()))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    let config = Arc::new(config);
    let worker = std::thread::Builder::new().name("openems-https".into()).spawn(move || {
        // Fixed workers bound concurrent handshakes and certificate generation.
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let listener = &listener;
                let config = &config;
                let allowed = &allowed;
                let stop = &stop;
                scope.spawn(move || {
                    while !stop.is_stopped() {
                        match listener.accept() {
                            Ok((socket, _)) => {
                                let _ = serve(socket, Arc::clone(config), allowed);
                            }
                            Err(_) => {
                                stop.wait(Duration::from_millis(50));
                            }
                        }
                    }
                });
            }
        });
    })?;
    Ok((address, worker))
}
