//! Linux integration: pure policy planning, read-only observations, and owned-file recovery.
//! Mutations are root-only and Linux-only. Unsupported features return an error, never an ACK.

use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use crate::fsutil::atomic_write;
use crate::locations::{Observed, normalize_mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

fn invalid(message: &str) -> AgentError {
    AgentError::Policy(message.into())
}

/// Read one security-backend setting without treating a commented or overridden value as active.
pub fn setting_value(text: &str, key: &str) -> Result<Option<String>> {
    let mut selected: Option<String> = None;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        let Some((name, raw)) = line.split_once('=') else { continue };
        if name.trim() != key {
            continue;
        }
        let raw = raw.trim();
        let value = if raw.starts_with('"') || raw.starts_with('\'') {
            let quote = raw.as_bytes()[0] as char;
            raw.strip_prefix(quote)
                .and_then(|value| value.strip_suffix(quote))
                .ok_or_else(|| invalid("unterminated backend setting"))?
        } else {
            raw
        };
        if value.is_empty() || selected.as_ref().is_some_and(|previous| previous != value) {
            return Err(invalid("empty or conflicting security-backend setting"));
        }
        selected = Some(value.to_owned());
    }
    Ok(selected)
}

pub fn resolv_conf_servers(text: &str) -> Vec<IpAddr> {
    let mut servers = Vec::new();
    for line in text.lines() {
        let mut fields = line.split('#').next().unwrap_or_default().split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        if let Some(ip) = fields.next().and_then(|text| text.parse::<IpAddr>().ok())
            && !ip.is_loopback()
            && !ip.is_unspecified()
            && !ip.is_multicast()
            && !servers.contains(&ip)
        {
            servers.push(ip);
        }
    }
    servers
}

pub fn observations_from_json(addresses: &Value, routes: &Value, neighbors: &Value, resolv: &str) -> Result<Observed> {
    let mut observed = Observed::default();
    let addresses = addresses.as_array().ok_or_else(|| invalid("invalid Linux adapter listing"))?;
    let routes = routes.as_array().ok_or_else(|| invalid("invalid Linux route listing"))?;
    let neighbors = neighbors.as_array().ok_or_else(|| invalid("invalid Linux neighbor listing"))?;
    let mut active = HashSet::new();
    for adapter in addresses {
        let Some(name) = adapter.get("ifname").and_then(Value::as_str) else { continue };
        if !adapter["flags"].as_array().is_some_and(|flags| flags.iter().any(|flag| flag == "UP")) {
            continue;
        }
        active.insert(name);
        for address in adapter["addr_info"].as_array().into_iter().flatten() {
            let Some(ip) = address["local"].as_str().and_then(|text| text.parse::<IpAddr>().ok()) else { continue };
            let Some(prefix) = address["prefixlen"].as_u64().and_then(|prefix| u8::try_from(prefix).ok()) else {
                continue;
            };
            if !ip.is_loopback() && !ip.is_unspecified() && prefix <= if ip.is_ipv4() { 32 } else { 128 } {
                observed.addresses.push((ip, prefix));
            }
        }
    }
    for route in routes {
        if !matches!(route["dst"].as_str(), Some("default" | "0.0.0.0/0" | "::/0")) {
            continue;
        }
        let (Some(device), Some(gateway)) = (route["dev"].as_str(), route["gateway"].as_str()) else { continue };
        if !active.contains(device) {
            continue;
        }
        for neighbor in neighbors {
            if neighbor["dev"] != device || neighbor["dst"] != gateway {
                continue;
            }
            if neighbor["state"].as_array().is_some_and(|states| {
                states.iter().any(|state| matches!(state.as_str(), Some("FAILED" | "INCOMPLETE")))
            }) {
                continue;
            }
            if let Some(mac) = neighbor["lladdr"].as_str().and_then(normalize_mac)
                && !observed.gateway_macs.contains(&mac)
            {
                observed.gateway_macs.push(mac);
            }
        }
    }
    for line in resolv.lines() {
        let mut fields = line.split('#').next().unwrap_or_default().split_whitespace();
        if !matches!(fields.next(), Some("search" | "domain")) {
            continue;
        }
        for suffix in fields {
            let suffix = suffix.trim_end_matches('.').to_ascii_lowercase();
            if !suffix.is_empty() && !observed.dns_suffixes.contains(&suffix) {
                observed.dns_suffixes.push(suffix);
            }
        }
    }
    Ok(observed)
}

/// The stub resolv.conf often contains only 127.0.0.53: use resolved's real servers first.
pub fn upstream_servers() -> Result<Vec<IpAddr>> {
    let mut servers = Vec::new();
    for path in ["/run/systemd/resolve/resolv.conf", "/var/lib/openems/upstream-resolv.conf", "/etc/resolv.conf"] {
        if let Ok(text) = std::fs::read_to_string(path) {
            for ip in resolv_conf_servers(&text) {
                if !servers.contains(&ip) {
                    servers.push(ip);
                }
            }
        }
    }
    if servers.is_empty() {
        return Err(AgentError::Local("no non-loopback upstream DNS servers are available".into()));
    }
    Ok(servers)
}

#[cfg(target_os = "linux")]
pub fn observed() -> Result<Observed> {
    let read = |args: &[&str]| -> Result<Value> {
        serde_json::from_slice(&command("ip", args)?).map_err(|_| invalid("invalid ip JSON response"))
    };
    let addresses = read(&["-j", "address", "show", "up"])?;
    let mut routes = read(&["-j", "-4", "route", "show", "default"])?;
    if let Ok(Value::Array(v6)) = read(&["-j", "-6", "route", "show", "default"])
        && let Some(routes) = routes.as_array_mut()
    {
        routes.extend(v6);
    }
    let neighbors = read(&["-j", "neighbor", "show"])?;
    observations_from_json(
        &addresses,
        &routes,
        &neighbors,
        &std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default(),
    )
}

#[cfg(not(target_os = "linux"))]
pub fn observed() -> Result<Observed> {
    Ok(Observed::default())
}

#[derive(Debug, Default)]
pub struct PolicyPlan {
    pub usbguard: Option<String>,
    pub fapolicyd: Option<String>,
    pub needs_hash_integrity: bool,
}

fn safe_attribute(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && value.chars().all(|c| c.is_ascii_alphanumeric() || "._-/".contains(c))
}

pub fn policy_plan(body: &Value) -> Result<PolicyPlan> {
    let mut plan = PolicyPlan::default();
    let usb = &body["usb_control"];
    let default = usb.get("default_action").and_then(Value::as_str).unwrap_or("allow");
    if !matches!(default, "allow" | "block") {
        return Err(invalid("Linux USBGuard supports allow/block, not read-only"));
    }
    let rules = usb.get("rules").and_then(Value::as_array).cloned().unwrap_or_default();
    if default != "allow" || !rules.is_empty() {
        let mut text = "# Managed by openems\nallow with-interface one-of { 03:*:* 09:*:* }\n".to_owned();
        for rule in rules {
            let action = rule["action"].as_str().ok_or_else(|| invalid("invalid USB action"))?;
            if !matches!(action, "allow" | "block") || rule.get("instance_id").is_some_and(|value| !value.is_null()) {
                return Err(invalid("Linux USBGuard cannot enforce read-only or Windows instance IDs"));
            }
            if rule["class"].as_str().is_some_and(|class| class != "storage") {
                return Err(invalid("only storage USB rules are supported"));
            }
            let mut rendered = action.to_owned();
            if rule.get("vid").is_some_and(|value| !value.is_null())
                || rule.get("pid").is_some_and(|value| !value.is_null())
            {
                let hex = |key: &str| -> Result<String> {
                    match rule.get(key).and_then(Value::as_str) {
                        None => Ok("*".into()),
                        Some(value) if value.len() == 4 && value.bytes().all(|c| c.is_ascii_hexdigit()) => {
                            Ok(value.to_ascii_lowercase())
                        }
                        _ => Err(invalid("invalid USB identifier")),
                    }
                };
                rendered.push_str(&format!(" id {}:{}", hex("vid")?, hex("pid")?));
            }
            if let Some(serial) = rule["serial"].as_str() {
                if !safe_attribute(serial) {
                    return Err(invalid("USB serial contains unsupported characters"));
                }
                rendered.push_str(&format!(" serial \"{serial}\""));
            }
            rendered.push_str(" with-interface equals { 08:*:* }\n");
            text.push_str(&rendered);
        }
        text.push_str(&format!("{default} with-interface equals {{ 08:*:* }}\n"));
        plan.usbguard = Some(text);
    }
    let apps = &body["app_control"];
    if apps["network_blocked"].as_array().is_some_and(|values| !values.is_empty()) {
        return Err(invalid("per-application network blocking is not supported on Linux"));
    }
    if let Some(rules) = apps["execution_rules"].as_array().filter(|rules| !rules.is_empty()) {
        let mut text = "# Managed by openems\n".to_owned();
        for rule in rules {
            let value = rule["value"].as_str().ok_or_else(|| invalid("invalid application rule value"))?;
            let attribute = match rule["kind"].as_str() {
                Some("hash") if value.len() == 64 && value.bytes().all(|c| c.is_ascii_hexdigit()) => {
                    plan.needs_hash_integrity = true;
                    format!("sha256hash={}", value.to_ascii_lowercase())
                }
                Some("path")
                    if value.starts_with('/')
                        && safe_attribute(value)
                        && !value.split('/').any(|part| part == "..") =>
                {
                    format!("path={value}")
                }
                _ => {
                    return Err(invalid(
                        "Linux execution rules support only SHA-256 hashes and absolute paths without whitespace",
                    ));
                }
            };
            text.push_str(&format!("deny_audit perm=execute all : {attribute}\n"));
        }
        plan.fapolicyd = Some(text);
    }
    Ok(plan)
}

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    applied: Vec<u8>,
    previous: Option<Vec<u8>>,
}

/// A write-ahead journal remembers both sides of an interrupted replacement. Unowned files are refused.
pub struct ManagedFiles {
    journal: PathBuf,
    allowed: Vec<PathBuf>,
}

impl ManagedFiles {
    pub fn new(journal: PathBuf, allowed: Vec<PathBuf>) -> Self {
        Self { journal, allowed }
    }

    fn load(&self) -> Result<BTreeMap<PathBuf, Entry>> {
        let text = match std::fs::read(&self.journal) {
            Ok(text) if text.len() <= 2 * 1024 * 1024 => text,
            Ok(_) => return Err(AgentError::State("platform journal is oversized".into())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(error) => return Err(error.into()),
        };
        let entries: BTreeMap<PathBuf, Entry> =
            serde_json::from_slice(&text).map_err(|_| AgentError::State("platform journal is invalid".into()))?;
        if entries.keys().any(|path| !self.allowed.contains(path)) {
            return Err(AgentError::State("platform journal names an unowned path".into()));
        }
        Ok(entries)
    }

    fn save(&self, entries: &BTreeMap<PathBuf, Entry>) -> Result<()> {
        atomic_write(
            &self.journal,
            &serde_json::to_vec(entries).map_err(|_| invalid("cannot encode platform journal"))?,
            None,
            true,
        )
    }

    fn current(path: &Path) -> Result<Option<Vec<u8>>> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(AgentError::State("platform target is not a regular file".into()));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        Ok(Some(std::fs::read(path)?))
    }

    fn verify(entries: &BTreeMap<PathBuf, Entry>) -> Result<()> {
        for (path, entry) in entries {
            if let Some(current) = Self::current(path)?
                && current != entry.applied
                && entry.previous.as_ref() != Some(&current)
            {
                return Err(AgentError::State(
                    "managed platform configuration changed outside openems; preserve journal and repair it".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn replace(&self, files: &[(PathBuf, Vec<u8>)]) -> Result<()> {
        let mut entries = self.load()?;
        Self::verify(&entries)?;
        let mut targets = HashSet::new();
        for (path, _) in files {
            if !self.allowed.contains(path) || !targets.insert(path.clone()) {
                return Err(invalid("unowned or duplicate platform target"));
            }
            if !entries.contains_key(path) && Self::current(path)?.is_some() {
                return Err(AgentError::State("platform target already exists and is not managed by openems".into()));
            }
        }
        for (path, data) in files {
            entries.insert(path.clone(), Entry { previous: Self::current(path)?, applied: data.clone() });
        }
        self.save(&entries)?;
        for (path, entry) in &entries {
            if targets.contains(path) {
                atomic_write(path, &entry.applied, None, false)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
                }
            } else if Self::current(path)?.is_some() {
                std::fs::remove_file(path)?;
            }
        }
        entries.retain(|path, _| targets.contains(path));
        for entry in entries.values_mut() {
            entry.previous = None;
        }
        if entries.is_empty() {
            if self.journal.exists() {
                std::fs::remove_file(&self.journal)?;
            }
        } else {
            self.save(&entries)?;
        }
        Ok(())
    }

    pub fn remove(&self) -> Result<()> {
        self.replace(&[])
    }
}

const DNS_DROPIN: &str = "/etc/systemd/resolved.conf.d/90-openems.conf";
const USB_RULES: &str = "/etc/usbguard/rules.d/00-openems-storage.conf";
const APP_RULES: &str = "/etc/fapolicyd/rules.d/00-openems-deny.rules";

fn policy_files(state: &Path) -> ManagedFiles {
    ManagedFiles::new(state.with_file_name("linux-policy-journal.json"), vec![USB_RULES.into(), APP_RULES.into()])
}
fn dns_files(state: &Path) -> ManagedFiles {
    ManagedFiles::new(state.with_file_name("linux-dns-journal.json"), vec![DNS_DROPIN.into()])
}

#[cfg(target_os = "linux")]
fn root() -> Result<()> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    if status.lines().find_map(|line| line.strip_prefix("Uid:")).and_then(|values| values.split_whitespace().nth(1))
        != Some("0")
    {
        return Err(AgentError::Local("platform configuration requires root".into()));
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn root() -> Result<()> {
    Err(AgentError::Local("this platform operation requires Linux".into()))
}

#[cfg(target_os = "linux")]
fn tool(name: &str) -> Result<PathBuf> {
    ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
        .iter()
        .map(|directory| Path::new(directory).join(name))
        .find(|path| path.is_file())
        .ok_or_else(|| AgentError::Local(format!("required Linux tool is missing: {name}")))
}

#[cfg(target_os = "linux")]
fn command(name: &str, args: &[&str]) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let mut child = Command::new(tool(name)?)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child.stdout.take().ok_or_else(|| AgentError::Local("command output is unavailable".into()))?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take(512 * 1024 + 1).read_to_end(&mut bytes).map(|_| bytes)
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let outcome = loop {
        match child.try_wait()? {
            Some(status) => break status.success(),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    let bytes = reader.join().map_err(|_| AgentError::Local("command output reader failed".into()))??;
    if !outcome || bytes.len() > 512 * 1024 {
        return Err(AgentError::Local(format!("Linux command failed or timed out: {name}")));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn active(name: &str) -> bool {
    command("systemctl", &["is-active", "--quiet", name]).is_ok()
}

pub fn dns_prepare(config: &AgentConfig) -> Result<()> {
    root()?;
    if !config.dns_filter {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        if config.dns_port != 53 || !active("systemd-resolved.service") {
            return Err(AgentError::Local("Linux DNS integration requires active systemd-resolved and local port 53; NetworkManager-only routing is unsupported".into()));
        }
        let domains = String::from_utf8_lossy(&command("resolvectl", &["domain"])?).into_owned();
        if domains
            .lines()
            .any(|line| line.trim_start().starts_with("Link ") && line.split_whitespace().any(|word| word == "~."))
        {
            return Err(AgentError::Local(
                "an existing per-link root DNS route conflicts with the managed resolver".into(),
            ));
        }
        let upstreams = upstream_servers()?;
        let snapshot = upstreams.iter().map(|ip| format!("nameserver {ip}\n")).collect::<String>();
        atomic_write(&config.state_path.with_file_name("upstream-resolv.conf"), snapshot.as_bytes(), None, true)?;
        dns_files(&config.state_path).replace(&[(
            DNS_DROPIN.into(),
            b"# Managed by openems\n[Resolve]\nDNS=127.0.0.1\nDomains=~.\nFallbackDNS=\n".to_vec(),
        )])?;
        if let Err(error) = command("systemctl", &["restart", "systemd-resolved.service"]) {
            let _ = dns_files(&config.state_path).remove();
            let _ = command("systemctl", &["restart", "systemd-resolved.service"]);
            return Err(error);
        }
    }
    Ok(())
}

pub fn dns_remove(state: &Path) -> Result<()> {
    root()?;
    let changed = state.with_file_name("linux-dns-journal.json").exists();
    dns_files(state).remove()?;
    #[cfg(target_os = "linux")]
    if changed {
        command("systemctl", &["restart", "systemd-resolved.service"])?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = changed;
    Ok(())
}

pub fn apply_policy(body: &Value, state: &Path) -> Result<Vec<String>> {
    let plan = policy_plan(body)?;
    if plan.usbguard.is_none()
        && plan.fapolicyd.is_none()
        && !state.with_file_name("linux-policy-journal.json").exists()
    {
        return Ok(Vec::new());
    }
    root()?;
    #[cfg(target_os = "linux")]
    {
        let mut files = Vec::new();
        if let Some(text) = &plan.usbguard {
            if !active("usbguard.service") {
                return Err(AgentError::Local("USBGuard must be installed and running".into()));
            }
            let config = std::fs::read_to_string("/etc/usbguard/usbguard-daemon.conf")?;
            if setting_value(&config, "RuleFolder")?.as_deref().map(|path| path.trim_end_matches('/'))
                != Some("/etc/usbguard/rules.d")
            {
                return Err(AgentError::Local("USBGuard must explicitly load /etc/usbguard/rules.d".into()));
            }
            let main_path = setting_value(&config, "RuleFile")?.unwrap_or_else(|| "/etc/usbguard/rules.conf".into());
            let main = match std::fs::read_to_string(main_path) {
                Ok(text) => text,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(error) => return Err(error.into()),
            };
            if main.lines().any(|line| !line.trim().is_empty() && !line.trim().starts_with('#')) {
                return Err(AgentError::Local("existing USBGuard main rules have precedence; configure a dedicated managed rule folder before enabling USB control".into()));
            }
            check_precedence(Path::new(USB_RULES))?;
            files.push((USB_RULES.into(), text.as_bytes().to_vec()));
        }
        if let Some(text) = &plan.fapolicyd {
            if !active("fapolicyd.service") {
                return Err(AgentError::Local("fapolicyd must be installed and running".into()));
            }
            if plan.needs_hash_integrity
                && setting_value(&std::fs::read_to_string("/etc/fapolicyd/fapolicyd.conf")?, "integrity")?.as_deref()
                    != Some("sha256")
            {
                return Err(AgentError::Local("SHA-256 execution rules require fapolicyd integrity=sha256".into()));
            }
            check_precedence(Path::new(APP_RULES))?;
            files.push((APP_RULES.into(), text.as_bytes().to_vec()));
        }
        let previous_usb = std::fs::read_to_string(USB_RULES).ok();
        let previous_apps = std::fs::read_to_string(APP_RULES).ok();
        let usb_changed = previous_usb != plan.usbguard;
        let apps_changed = previous_apps != plan.fapolicyd;
        policy_files(state).replace(&files)?;
        if usb_changed {
            // The upstream USBGuard unit has no ExecReload. Restart only after content changes.
            command("systemctl", &["restart", "usbguard.service"])?;
        }
        if apps_changed {
            command("fagenrules", &["--load"])?;
        }
        return Ok(files.iter().map(|(path, _)| path.to_string_lossy().into_owned()).collect());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (plan, state);
        Ok(Vec::new())
    }
}

#[cfg(target_os = "linux")]
fn check_precedence(target: &Path) -> Result<()> {
    let directory = target.parent().ok_or_else(|| invalid("invalid managed rule path"))?;
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        if path.as_path() < target && path.is_file() {
            let text = std::fs::read_to_string(path)?;
            if text.lines().any(|line| !line.trim().is_empty() && !line.trim().starts_with('#')) {
                return Err(AgentError::Local("an existing rule file precedes the managed policy".into()));
            }
        }
    }
    Ok(())
}

pub fn remove_policy(state: &Path) -> Result<()> {
    root()?;
    let managed = state.with_file_name("linux-policy-journal.json").exists();
    policy_files(state).remove()?;
    #[cfg(target_os = "linux")]
    {
        if managed && active("usbguard.service") {
            command("systemctl", &["restart", "usbguard.service"])?;
        }
        if managed && active("fapolicyd.service") {
            command("fagenrules", &["--load"])?;
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = managed;
    Ok(())
}

pub fn capability_tags() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        let mut tags = vec!["platform:linux".into()];
        if active("systemd-resolved.service") {
            tags.push("web-filter:systemd-resolved".into());
        }
        if active("usbguard.service") {
            tags.push("usb-control:usbguard-allow-block".into());
        }
        if active("fapolicyd.service") {
            tags.push("app-control:fapolicyd-path-hash".into());
        }
        tags
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}
