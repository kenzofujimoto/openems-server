//! Read-only network observations. Unknown adapters, neighbors and TLS probes never count as signals.

use crate::error::Result;
use crate::locations::{Location, Observed, Probe};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
static LOOKUPS: AtomicUsize = AtomicUsize::new(0);
static PROBE_CURSOR: AtomicUsize = AtomicUsize::new(0);
const PROBE_WORKERS: usize = 4;

/// All probes share a two-second collection budget so many unreachable sites cannot stall enforcement.
pub fn collect(locations: &[Location]) -> Result<Observed> {
    let mut observed = adapter_signals()?;
    let deadline = Instant::now() + PROBE_TIMEOUT;
    let mut seen = std::collections::HashSet::new();
    let mut probes: Vec<_> = locations
        .iter()
        .filter_map(|location| location.probe.as_ref())
        .filter(|probe| seen.insert((probe.host.clone(), probe.port, probe.sha256.clone())))
        .collect();
    if probes.is_empty() {
        return Ok(observed);
    }
    // Rotate the starting point when more than four probes saturate the deadline. Even if all
    // earlier sites are silent, a lower-priority healthy site is not starved forever.
    let start = PROBE_CURSOR.fetch_add(PROBE_WORKERS, Ordering::Relaxed) % probes.len();
    probes.rotate_left(start);
    let next = AtomicUsize::new(0);
    let batches = std::thread::scope(|scope| -> Result<Vec<_>> {
        let handles: Vec<_> = (0..probes.len().min(PROBE_WORKERS))
            .map(|_| {
                let probes = &probes;
                let next = &next;
                scope.spawn(move || {
                    let mut results = Vec::new();
                    while Instant::now() < deadline {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(probe) = probes.get(index) else { break };
                        results.push(((probe.host.clone(), probe.port), probe_before(probe, deadline)));
                    }
                    results
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| {
                handle.join().map_err(|_| crate::error::AgentError::Local("network probe worker terminated".into()))
            })
            .collect()
    })?;
    for (key, result) in batches.into_iter().flatten() {
        if result.is_some() || !observed.probes.contains_key(&key) {
            observed.probes.insert(key, result);
        }
    }
    Ok(observed)
}

/// Read the pinned peer certificate after a complete, signed TLS handshake. No application data is sent.
pub fn probe_certificate(probe: &Probe) -> Option<String> {
    probe_before(probe, Instant::now() + PROBE_TIMEOUT)
}

fn remaining(deadline: Instant) -> std::io::Result<Duration> {
    let duration = deadline.saturating_duration_since(Instant::now());
    if duration.is_zero() { Err(std::io::ErrorKind::TimedOut.into()) } else { Ok(duration) }
}

/// OS DNS lookups have no cancellable std API. Bound both wait time and outstanding resolver threads.
fn resolve(probe: &Probe, deadline: Instant) -> Option<Vec<SocketAddr>> {
    if let Ok(ip) = probe.host.parse::<IpAddr>() {
        return Some(vec![SocketAddr::new(ip, probe.port)]);
    }
    if LOOKUPS.fetch_add(1, Ordering::AcqRel) >= 4 {
        LOOKUPS.fetch_sub(1, Ordering::AcqRel);
        return None;
    }
    let host = probe.host.clone();
    let port = probe.port;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    if std::thread::Builder::new()
        .name("openems-probe-dns".into())
        .spawn(move || {
            struct LookupGuard;
            impl Drop for LookupGuard {
                fn drop(&mut self) {
                    LOOKUPS.fetch_sub(1, Ordering::AcqRel);
                }
            }
            let _guard = LookupGuard;
            let result = (host.as_str(), port).to_socket_addrs().map(|addresses| addresses.take(8).collect::<Vec<_>>());
            let _ = sender.send(result);
        })
        .is_err()
    {
        LOOKUPS.fetch_sub(1, Ordering::AcqRel);
        return None;
    }
    receiver.recv_timeout(remaining(deadline).ok()?).ok()?.ok()
}

#[derive(Debug)]
struct PinVerifier {
    pin: String,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if hex::encode(Sha256::digest(end_entity.as_ref())).eq_ignore_ascii_case(&self.pin) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// Refresh the timeout before every I/O: a trickling peer cannot extend the handshake deadline.
struct DeadlineSocket {
    socket: TcpStream,
    deadline: Instant,
}
impl Read for DeadlineSocket {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.socket.set_read_timeout(Some(remaining(self.deadline)?))?;
        self.socket.read(bytes)
    }
}
impl Write for DeadlineSocket {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.socket.set_write_timeout(Some(remaining(self.deadline)?))?;
        self.socket.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.socket.flush()
    }
}

fn probe_before(probe: &Probe, deadline: Instant) -> Option<String> {
    let server_name = ServerName::try_from(probe.host.clone()).ok()?;
    let addresses = resolve(probe, deadline)?;
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .ok()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier { pin: probe.sha256.clone() }))
        .with_no_client_auth();
    let config = Arc::new(config);
    for (index, address) in addresses.iter().enumerate() {
        // A silent first address (commonly IPv6 on an IPv4-only network) must not spend the
        // entire probe deadline. Share the remaining time across candidates and reserve one
        // share for the TLS handshake after connecting.
        let shares = u32::try_from(addresses.len() - index + 1).ok()?;
        let connect_timeout = remaining(deadline).ok()? / shares;
        if connect_timeout.is_zero() {
            return None;
        }
        let Ok(socket) = TcpStream::connect_timeout(address, connect_timeout) else { continue };
        let mut socket = DeadlineSocket { socket, deadline };
        let mut connection = rustls::ClientConnection::new(Arc::clone(&config), server_name.clone()).ok()?;
        let mut verified = true;
        while connection.is_handshaking() {
            if connection.complete_io(&mut socket).is_err() {
                verified = false;
                break;
            }
        }
        if verified && !connection.is_handshaking() {
            let cert = connection.peer_certificates()?.first()?;
            return Some(hex::encode(Sha256::digest(cert.as_ref())));
        }
    }
    None
}

#[cfg(windows)]
fn adapter_signals() -> Result<Observed> {
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        GetAdaptersAddresses, GetIpNetEntry2, IP_ADAPTER_ADDRESSES_LH, MIB_IPNET_ROW2,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6};

    unsafe fn ip(address: *const SOCKADDR) -> Option<IpAddr> {
        // SAFETY: the caller provides a live socket address returned by GetAdaptersAddresses.
        unsafe {
            if address.is_null() {
                return None;
            }
            match (*address).sa_family {
                AF_INET => Some(IpAddr::from((*address.cast::<SOCKADDR_IN>()).sin_addr.S_un.S_addr.to_ne_bytes())),
                AF_INET6 => Some(IpAddr::from((*address.cast::<SOCKADDR_IN6>()).sin6_addr.u.Byte)),
                _ => None,
            }
        }
    }
    let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size = 16 * 1024;
    for _ in 0..4 {
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        let first = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: aligned storage is live and `size` is its byte capacity.
        let status = unsafe { GetAdaptersAddresses(u32::from(AF_UNSPEC), flags, std::ptr::null(), first, &mut size) };
        if status == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if status == ERROR_NO_DATA {
            return Ok(Observed::default());
        }
        if status != NO_ERROR {
            return Err(crate::error::AgentError::Local("cannot read network adapters".into()));
        }
        let mut observed = Observed::default();
        let mut adapter = first;
        // SAFETY: all pointers are OS-produced linked lists within the live adapter buffer.
        unsafe {
            while !adapter.is_null() {
                let current = &*adapter;
                if current.OperStatus == IfOperStatusUp {
                    let mut address = current.FirstUnicastAddress;
                    while !address.is_null() {
                        if let Some(ip) = ip((*address).Address.lpSockaddr)
                            && !ip.is_loopback()
                            && !ip.is_unspecified()
                        {
                            observed.addresses.push((ip, (*address).OnLinkPrefixLength));
                        }
                        address = (*address).Next;
                    }
                    if !current.DnsSuffix.is_null() {
                        let length = (0..1024).take_while(|index| *current.DnsSuffix.add(*index) != 0).count();
                        if length > 0 && length < 1024 {
                            observed
                                .dns_suffixes
                                .push(String::from_utf16_lossy(std::slice::from_raw_parts(current.DnsSuffix, length)));
                        }
                    }
                    let mut gateway = current.FirstGatewayAddress;
                    while !gateway.is_null() {
                        let address = (*gateway).Address.lpSockaddr;
                        if !address.is_null() {
                            let mut row = MIB_IPNET_ROW2 { InterfaceLuid: current.Luid, ..Default::default() };
                            match (*address).sa_family {
                                AF_INET => row.Address.Ipv4 = *address.cast::<SOCKADDR_IN>(),
                                AF_INET6 => row.Address.Ipv6 = *address.cast::<SOCKADDR_IN6>(),
                                _ => {
                                    gateway = (*gateway).Next;
                                    continue;
                                }
                            }
                            // Passive neighbor lookup: no ARP requests or changes to adapter settings.
                            if GetIpNetEntry2(&mut row) == NO_ERROR && row.PhysicalAddressLength == 6 {
                                observed.gateway_macs.push(hex::encode(&row.PhysicalAddress[..6]));
                            }
                        }
                        gateway = (*gateway).Next;
                    }
                }
                adapter = current.Next;
            }
        }
        return Ok(observed);
    }
    Err(crate::error::AgentError::Local("network adapter list keeps growing; retry later".into()))
}

#[cfg(not(windows))]
fn adapter_signals() -> Result<Observed> {
    // Until F8 adds native interface enumeration, unsupported local signals remain unknown.
    Ok(Observed::default())
}
