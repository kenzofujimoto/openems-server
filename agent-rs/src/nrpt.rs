//! NRPT rule routing every name to the loopback resolver (Windows). The service creates it only
//! after the resolver listens and removes it on a graceful stop; a crash leaves it in place, so
//! killing the process does not turn filtering off.
use crate::error::{AgentError, Result};
use std::net::IpAddr;

/// Identifies the rule this agent owns; other NRPT rules (VPN, GPO) are never touched.
pub const RULE_COMMENT: &str = "openems-agent managed DNS filter";
const LOOPBACKS: &str = "@('127.0.0.1','::1')";

fn removal_line() -> String {
    format!(
        "Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{RULE_COMMENT}' -and @($_.Namespace) -contains '.' \
         -and @(@($_.NameServers) | Where-Object {{ $_ -notin {LOOPBACKS} }}).Count -eq 0 }} \
         | ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force }}"
    )
}

pub fn remove_script() -> String {
    format!("$ErrorActionPreference = 'Stop'\n{}\nClear-DnsClientCache\n", removal_line())
}

/// Replace managed leftovers, then route the root namespace to loopback servers only.
pub fn install_script(servers: &[IpAddr]) -> Result<String> {
    if servers.is_empty() || !servers.iter().all(IpAddr::is_loopback) {
        return Err(AgentError::Local("NRPT rule accepts only loopback resolvers".into()));
    }
    let list = servers.iter().map(|server| format!("'{server}'")).collect::<Vec<_>>().join(",");
    Ok(format!(
        "$ErrorActionPreference = 'Stop'\n{}\nAdd-DnsClientNrptRule -Namespace '.' -NameServers @({list}) -Comment '{RULE_COMMENT}' | Out-Null\nClear-DnsClientCache\n",
        removal_line()
    ))
}

/// Base64 of UTF-16LE, the form `powershell -EncodedCommand` expects; avoids quoting rules.
pub fn encode_command(script: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let block = [chunk[0], chunk.get(1).copied().unwrap_or(0), chunk.get(2).copied().unwrap_or(0)];
        let value = u32::from(block[0]) << 16 | u32::from(block[1]) << 8 | u32::from(block[2]);
        for index in 0..4 {
            encoded.push(if index <= chunk.len() {
                ALPHABET[(value >> (18 - 6 * index)) as usize & 63] as char
            } else {
                '='
            });
        }
    }
    encoded
}

#[cfg(windows)]
fn run(script: &str) -> Result<()> {
    let root = std::env::var_os("SystemRoot").map_or_else(|| std::path::PathBuf::from(r"C:\Windows"), Into::into);
    let output = std::process::Command::new(root.join(r"System32\WindowsPowerShell\v1.0\powershell.exe"))
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand"])
        .arg(encode_command(script))
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail: String =
        stderr.lines().find(|line| !line.trim().is_empty()).unwrap_or("unknown error").chars().take(300).collect();
    Err(AgentError::Local(format!("NRPT update failed: {detail}")))
}

#[cfg(not(windows))]
fn run(_: &str) -> Result<()> {
    Err(AgentError::Local("NRPT routing requires Windows".into()))
}

pub fn install(servers: &[IpAddr]) -> Result<()> {
    run(&install_script(servers)?)
}

pub fn remove() -> Result<()> {
    run(&remove_script())
}
