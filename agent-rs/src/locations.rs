//! Network locations (network-locations.md). The server sends each location mapped to this machine's
//! group, with the full policy that applies inside it; the agent decides every cycle, even offline.
//! A location matches on the office public address, or on at least two kinds of local signals.
//! Anything unknown or malformed keeps the stricter outside policy.

use crate::error::Result;
use crate::policy::{Assignment, validate_assignment};
use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;

/// Signals kinds other than the public address needed for a match.
const LOCAL_SIGNALS_NEEDED: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Range {
    network: IpAddr,
    prefix: u8,
}

impl Range {
    pub fn parse(text: &str) -> Option<Range> {
        let (address, prefix) = text.trim().split_once('/')?;
        let network: IpAddr = address.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        let width = if network.is_ipv4() { 32 } else { 128 };
        (prefix <= width).then_some(Range { network, prefix })
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.prefix)).unwrap_or(0);
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(self.prefix)).unwrap_or(0);
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub host: String,
    pub port: u16,
    /// Lowercase hex SHA-256 of the server's end-entity certificate (DER).
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct Location {
    pub id: String,
    pub name: String,
    pub cidrs: Vec<Range>,
    pub gateway_macs: Vec<String>,
    pub dns_suffixes: Vec<String>,
    pub public_cidrs: Vec<Range>,
    pub probe: Option<Probe>,
    pub assignment: Assignment,
}

/// What the machine sees now. Unknown values (no server contact, probe not reachable) never match.
#[derive(Debug, Clone, Default)]
pub struct Observed {
    pub addresses: Vec<(IpAddr, u8)>,
    pub gateway_macs: Vec<String>,
    pub dns_suffixes: Vec<String>,
    pub public_ip: Option<IpAddr>,
    /// (host, port) → hex SHA-256 of the certificate, None when it could not be read.
    pub probes: HashMap<(String, u16), Option<String>>,
}

/// "00:11:22:33:44:55", "00-11-22-33-44-55" and "001122334455" compare equal.
pub fn normalize_mac(text: &str) -> Option<String> {
    let hex: String = text.chars().filter(|character| !matches!(character, ':' | '-' | '.' | ' ')).collect();
    (hex.len() == 12 && hex.chars().all(|character| character.is_ascii_hexdigit())).then(|| hex.to_ascii_lowercase())
}

fn normalize_suffix(text: &str) -> String {
    text.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn dns_name(text: &str) -> Option<String> {
    let normalized = normalize_suffix(text);
    (normalized.len() <= 253
        && normalized.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        }))
    .then_some(normalized)
}

fn strings(value: &Value, key: &str) -> Option<Vec<String>> {
    match value.get(key) {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(Value::Array(items)) => items.iter().map(|item| item.as_str().map(str::to_owned)).collect(),
        Some(_) => None,
    }
}

fn ranges(value: &Value, key: &str) -> Option<Vec<Range>> {
    strings(value, key)?.iter().map(|text| Range::parse(text)).collect()
}

fn parse_location(value: &Value) -> Option<Location> {
    let text = |key: &str| value.get(key).and_then(Value::as_str).filter(|text| !text.is_empty()).map(str::to_owned);
    let probe = match value.get("probe") {
        None | Some(Value::Null) => None,
        Some(probe) => Some(Probe {
            host: dns_name(probe.get("host")?.as_str()?)?,
            port: u16::try_from(probe.get("port")?.as_u64()?).ok().filter(|port| *port > 0)?,
            sha256: probe
                .get("sha256")?
                .as_str()
                .filter(|pin| pin.len() == 64 && pin.chars().all(|character| character.is_ascii_hexdigit()))?
                .to_ascii_lowercase(),
        }),
    };
    Some(Location {
        id: text("id")?,
        name: text("name")?,
        cidrs: ranges(value, "cidrs")?,
        gateway_macs: strings(value, "gateway_macs")?.iter().map(|mac| normalize_mac(mac)).collect::<Option<_>>()?,
        dns_suffixes: strings(value, "dns_suffixes")?.iter().map(|suffix| dns_name(suffix)).collect::<Option<_>>()?,
        public_cidrs: ranges(value, "public_cidrs")?,
        probe,
        // The inside policy is verified like the outside one: a tampered body is refused.
        assignment: validate_assignment(value.get("assignment")?).ok()?,
    })
}

/// Locations from a validated config/assigned response, in priority order. Malformed entries are skipped:
/// they can only make the machine stay outside, never weaken the outside policy.
pub fn parse_locations(raw: &Value) -> Result<Vec<Location>> {
    Ok(raw
        .get("locations")
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |items| items.iter().filter_map(parse_location).collect()))
}

/// The source address the server saw for this machine.
pub fn client_ip(raw: &Value) -> Option<IpAddr> {
    raw.get("client_ip")?.as_str()?.parse().ok()
}

fn matches(location: &Location, observed: &Observed) -> bool {
    if observed.public_ip.is_some_and(|public| location.public_cidrs.iter().any(|range| range.contains(public))) {
        return true;
    }
    let cidr =
        observed.addresses.iter().any(|(address, _)| location.cidrs.iter().any(|range| range.contains(*address)));
    let gateway = observed
        .gateway_macs
        .iter()
        .filter_map(|mac| normalize_mac(mac))
        .any(|mac| location.gateway_macs.contains(&mac));
    let suffix = observed
        .dns_suffixes
        .iter()
        .map(|suffix| normalize_suffix(suffix))
        .any(|suffix| location.dns_suffixes.contains(&suffix));
    let probe = location.probe.as_ref().is_some_and(|probe| {
        observed
            .probes
            .get(&(probe.host.clone(), probe.port))
            .and_then(Option::as_deref)
            .is_some_and(|seen| seen.eq_ignore_ascii_case(&probe.sha256))
    });
    [cidr, gateway, suffix, probe].into_iter().filter(|matched| *matched).count() >= LOCAL_SIGNALS_NEEDED
}

/// The first location the machine is in, or None (outside).
pub fn choose<'a>(locations: &'a [Location], observed: &Observed) -> Option<&'a Location> {
    locations.iter().find(|location| matches(location, observed))
}
