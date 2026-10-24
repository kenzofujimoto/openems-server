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

/// Whether the managed rule exists, read from the local NRPT store in the registry (no PowerShell).
#[cfg(windows)]
pub fn is_installed() -> Result<bool> {
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RRF_RT_REG_SZ, RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW,
    };
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    const ERROR_NO_MORE_ITEMS: u32 = 259;
    let wide = |text: &str| -> Vec<u16> { text.encode_utf16().chain([0]).collect() };
    let path = wide(r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig");
    let comment = wide("Comment");
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: NUL-terminated path; the key is closed below.
    let status = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut key) };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(false);
    }
    if status != 0 {
        return Err(AgentError::Local(format!("NRPT store not readable (error {status})")));
    }
    let mut found = Ok(false);
    for index in 0.. {
        let mut name = [0u16; 256];
        let mut length = name.len() as u32 - 1;
        let null: *mut u32 = std::ptr::null_mut();
        // SAFETY: buffer and length describe `name`; optional outputs are null.
        let status = unsafe {
            RegEnumKeyExW(
                key,
                index,
                name.as_mut_ptr(),
                &mut length,
                null.cast(),
                std::ptr::null_mut(),
                null.cast(),
                std::ptr::null_mut(),
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        if status != 0 {
            found = Err(AgentError::Local(format!("NRPT store not readable (error {status})")));
            break;
        }
        let mut value = [0u16; 512];
        let mut size = (value.len() * 2) as u32;
        // SAFETY: `name` is NUL-terminated by the enumeration; value buffer size is in bytes.
        let read = unsafe {
            RegGetValueW(
                key,
                name.as_ptr(),
                comment.as_ptr(),
                RRF_RT_REG_SZ,
                null,
                value.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if read == 0 {
            let text = String::from_utf16_lossy(&value[..value.iter().position(|&unit| unit == 0).unwrap_or(0)]);
            if text == RULE_COMMENT {
                found = Ok(true);
                break;
            }
        }
    }
    // SAFETY: key opened above.
    unsafe { RegCloseKey(key) };
    found
}

pub fn install(servers: &[IpAddr]) -> Result<()> {
    run(&install_script(servers)?)
}

pub fn remove() -> Result<()> {
    run(&remove_script())
}
