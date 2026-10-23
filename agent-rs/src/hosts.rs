//! Managed block inside the system hosts file, byte-compatible with the Python agent.

use crate::error::{AgentError, Result};
use crate::fsutil::atomic_write;
use crate::policy::WebRules;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const HOSTS_BEGIN: &str = "# >>> openems managed block >>>";
pub const HOSTS_END: &str = "# <<< openems managed block <<<";

#[cfg(windows)]
pub const DEFAULT_HOSTS: &str = r"C:\Windows\System32\drivers\etc\hosts";
#[cfg(not(windows))]
pub const DEFAULT_HOSTS: &str = "/etc/hosts";

pub fn render_hosts_block(rules: &WebRules, ip: &str) -> Result<String> {
    if ip != "0.0.0.0" && ip != "127.0.0.1" {
        return Err(AgentError::Local("unsupported hosts target".into()));
    }
    let names = rules.hosts_names();
    let mut lines = vec![HOSTS_BEGIN.to_owned()];
    lines.extend(names.iter().map(|name| format!("{ip} {name}")));
    lines.push(HOSTS_END.to_owned());
    Ok(lines.join("\n") + "\n")
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack.windows(needle.len()).filter(|window| *window == needle).count()
}

/// Byte range of the managed block including its trailing newline, if present.
fn managed_span(current: &[u8]) -> Result<Option<(usize, usize)>> {
    let (begin, end) = (HOSTS_BEGIN.as_bytes(), HOSTS_END.as_bytes());
    let begins = count(current, begin);
    if begins != count(current, end) || begins > 1 {
        return Err(AgentError::Local("hosts contains malformed managed markers".into()));
    }
    let Some(start) = find(current, begin) else { return Ok(None) };
    let Some(offset) = find(&current[start..], end) else {
        return Err(AgentError::Local("hosts contains reversed managed markers".into()));
    };
    let mut stop = start + offset + end.len();
    if current[stop..].starts_with(b"\r\n") {
        stop += 2;
    } else if current[stop..].starts_with(b"\n") {
        stop += 1;
    }
    Ok(Some((start, stop)))
}

pub fn replace_managed_block(current: &[u8], block: &[u8]) -> Result<Vec<u8>> {
    match managed_span(current)? {
        Some((start, stop)) => Ok([&current[..start], block, &current[stop..]].concat()),
        None => {
            let mut updated = current.to_vec();
            if !current.is_empty() && !current.ends_with(b"\n") {
                updated.push(b'\n');
            }
            updated.extend_from_slice(block);
            Ok(updated)
        }
    }
}

fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".openems.bak");
    path.with_file_name(name)
}

fn is_system_hosts(path: &Path) -> bool {
    match (fs::canonicalize(path), fs::canonicalize(DEFAULT_HOSTS)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

pub fn flush_dns() -> Result<()> {
    let command = if cfg!(windows) {
        Some(("ipconfig", vec!["/flushdns"]))
    } else if cfg!(target_os = "macos") {
        Some(("dscacheutil", vec!["-flushcache"]))
    } else {
        Some(("resolvectl", vec!["flush-caches"]))
    };
    let Some((program, args)) = command else { return Ok(()) };
    match Command::new(program).args(&args).output() {
        Ok(output) if output.status.success() => Ok(()),
        Ok(_) => Err(AgentError::Local("DNS cache flush failed".into())),
        // Linux without systemd-resolved has no cache to flush.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !cfg!(windows) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn write_hosts(path: &Path, previous: &[u8], updated: &[u8]) -> Result<bool> {
    if previous == updated {
        return Ok(false);
    }
    match OpenOptions::new().write(true).create_new(true).open(backup_path(path)) {
        Ok(mut backup) => backup.write_all(previous)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    atomic_write(path, updated, Some(previous), false)?;
    if is_system_hosts(path)
        && let Err(error) = flush_dns()
    {
        atomic_write(path, previous, Some(updated), false)?;
        return Err(error);
    }
    Ok(true)
}

fn read_or_empty(path: &Path) -> Result<Vec<u8>> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}

pub fn apply_hosts(rules: &WebRules, path: &Path, ip: &str) -> Result<bool> {
    let block = render_hosts_block(rules, ip)?;
    let previous = read_or_empty(path)?;
    let updated = replace_managed_block(&previous, block.as_bytes())?;
    write_hosts(path, &previous, &updated)
}

pub fn clear_hosts(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let previous = fs::read(path)?;
    let mut updated = match managed_span(&previous)? {
        Some((start, stop)) => [&previous[..start], &previous[stop..]].concat(),
        None => previous.clone(),
    };
    if let Ok(original) = fs::read(backup_path(path)) {
        // Drop the separator we added only when everything else still matches the backup.
        if !original.is_empty() && !original.ends_with(b"\n") && updated == [original.as_slice(), b"\n"].concat() {
            updated = original;
        }
    }
    write_hosts(path, &previous, &updated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domains(values: &[&str]) -> WebRules {
        WebRules::new(&values.iter().map(|value| (*value).to_owned()).collect::<Vec<_>>(), &[]).unwrap()
    }

    #[test]
    fn block_includes_www_variants_once() {
        let block = render_hosts_block(&domains(&["Example.com", "www.site.io", "example.com"]), "0.0.0.0").unwrap();
        assert_eq!(
            block,
            format!("{HOSTS_BEGIN}\n0.0.0.0 example.com\n0.0.0.0 www.example.com\n0.0.0.0 www.site.io\n{HOSTS_END}\n")
        );
        assert!(render_hosts_block(&domains(&["example.com"]), "10.0.0.1").is_err());
    }

    #[test]
    fn apply_and_clear_preserve_foreign_entries_and_line_endings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        fs::write(&path, b"127.0.0.1 localhost\r\n10.0.0.5 intranet").unwrap();
        assert!(apply_hosts(&domains(&["example.com"]), &path, "0.0.0.0").unwrap());
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("127.0.0.1 localhost\r\n10.0.0.5 intranet\n# >>> openems"));
        assert!(!apply_hosts(&domains(&["example.com"]), &path, "0.0.0.0").unwrap(), "reapplying is idempotent");
        assert!(apply_hosts(&domains(&["other.com"]), &path, "127.0.0.1").unwrap());
        assert!(fs::read_to_string(&path).unwrap().contains("127.0.0.1 other.com"));
        assert!(clear_hosts(&path).unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"127.0.0.1 localhost\r\n10.0.0.5 intranet");
    }

    #[test]
    fn malformed_markers_are_never_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        for content in [
            format!("{HOSTS_END}\n{HOSTS_BEGIN}\n"),
            format!("{HOSTS_BEGIN}\n"),
            format!("{HOSTS_BEGIN}\n{HOSTS_END}\n{HOSTS_BEGIN}\n{HOSTS_END}\n"),
        ] {
            fs::write(&path, &content).unwrap();
            assert!(apply_hosts(&domains(&["example.com"]), &path, "0.0.0.0").is_err());
            assert!(clear_hosts(&path).is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), content);
        }
    }

    #[test]
    fn missing_files_are_created_and_clearing_nothing_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        assert!(!clear_hosts(&path).unwrap());
        assert!(apply_hosts(&domains(&["example.com"]), &path, "0.0.0.0").unwrap());
        assert!(fs::read_to_string(&path).unwrap().starts_with(HOSTS_BEGIN));
    }
}
