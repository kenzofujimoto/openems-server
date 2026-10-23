//! Recoverable installer transaction. Tests use an isolated backend, never machine trust.

use crate::authority::{self, Authority, TrustStore};
use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};

fn failure(message: &str) -> AgentError {
    AgentError::Local(format!("installer transaction: {message}"))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSnapshot {
    path: PathBuf,
    bytes: Option<Vec<u8>>,
    security: Vec<u8>,
    allowed: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u8,
    config: PathBuf,
    files: Vec<FileSnapshot>,
    root_before: Option<Vec<u8>>,
    trusted_before: bool,
    root_active: Option<Vec<u8>>,
}

trait TransactionBackend {
    fn validate(&mut self, files: &[FileSnapshot]) -> Result<()>;
    fn trusted(&mut self, root: &[u8]) -> Result<bool>;
    fn trust(&mut self, root: &[u8]) -> Result<()>;
    fn untrust(&mut self, root: &[u8]) -> Result<()>;
    fn restore(&mut self, files: &[FileSnapshot]) -> Result<()>;
}

fn restore_transaction(saved: &Journal, backend: &mut impl TransactionBackend) -> Result<()> {
    backend.validate(&saved.files)?;
    if let Some(root) = &saved.root_active
        && !(saved.trusted_before && saved.root_before.as_ref() == Some(root))
    {
        backend.untrust(root)?;
    }
    backend.restore(&saved.files)?;
    if saved.trusted_before {
        let root = saved.root_before.as_ref().ok_or_else(|| failure("missing original root identity"))?;
        if !backend.trusted(root)? {
            backend.trust(root)?;
        }
    }
    Ok(())
}

struct Machine;
impl TransactionBackend for Machine {
    fn validate(&mut self, files: &[FileSnapshot]) -> Result<()> {
        for saved in files {
            authority::check_path(&saved.path)?;
            if !saved.allowed.contains(&file_identity(&saved.path)?) {
                return Err(failure("snapshot target changed outside the transaction; manual recovery required"));
            }
        }
        Ok(())
    }
    fn trusted(&mut self, root: &[u8]) -> Result<bool> {
        #[cfg(windows)]
        {
            authority::WindowsTrustStore.contains(root)
        }
        #[cfg(not(windows))]
        {
            let _ = root;
            Err(failure("Windows required"))
        }
    }
    fn trust(&mut self, root: &[u8]) -> Result<()> {
        #[cfg(windows)]
        {
            authority::WindowsTrustStore.add(root)
        }
        #[cfg(not(windows))]
        {
            let _ = root;
            Err(failure("Windows required"))
        }
    }
    fn untrust(&mut self, root: &[u8]) -> Result<()> {
        #[cfg(windows)]
        {
            authority::WindowsTrustStore.remove(root)
        }
        #[cfg(not(windows))]
        {
            let _ = root;
            Err(failure("Windows required"))
        }
    }
    fn restore(&mut self, files: &[FileSnapshot]) -> Result<()> {
        for saved in files {
            authority::check_path(&saved.path)?;
            match &saved.bytes {
                Some(bytes) => {
                    // The journal is SYSTEM-only and never stores plaintext DPAPI private keys.
                    crate::fsutil::atomic_write(&saved.path, bytes, None, true)?;
                    restore_security(&saved.path, &saved.security)?;
                }
                None => match fs::remove_file(&saved.path) {
                    Ok(()) => (),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                    Err(error) => return Err(error.into()),
                },
            }
        }
        if files.iter().any(|saved| saved.path == Path::new(crate::hosts::DEFAULT_HOSTS)) {
            crate::hosts::flush_dns()?;
        }
        Ok(())
    }
}

fn transaction_dir(config: &Path) -> Result<PathBuf> {
    let parent = config.parent().ok_or_else(|| failure("configuration needs a parent directory"))?;
    Ok(parent.join("installer-transaction"))
}
fn save(directory: &Path, saved: &Journal) -> Result<()> {
    authority::verify_authority_file(directory)?;
    let path = directory.join("journal.json");
    authority::check_path(&path)?;
    if path.try_exists()? {
        authority::verify_authority_file(&path)?;
    }
    let bytes = serde_json::to_vec(saved).map_err(|_| failure("cannot encode journal"))?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(failure("journal exceeds size limit"));
    }
    // A SYSTEM-only parent prevents the generic private-file ACL from exposing data.
    crate::fsutil::atomic_write(&path, &bytes, None, true)?;
    authority::secure_authority_file(&path)?;
    authority::verify_authority_file(&path)
}
fn read(config: &Path) -> Result<Option<(PathBuf, Journal)>> {
    authority::require_system()?;
    authority::check_path(config)?;
    let directory = transaction_dir(config)?;
    authority::check_path(&directory)?;
    if !directory.try_exists()? {
        return Ok(None);
    }
    authority::verify_authority_file(&directory)?;
    let path = directory.join("journal.json");
    authority::verify_authority_file(&path)?;
    if fs::metadata(&path)?.len() > 16 * 1024 * 1024 {
        return Err(failure("journal exceeds size limit"));
    }
    let saved: Journal = serde_json::from_slice(&fs::read(&path)?).map_err(|_| failure("corrupt journal"))?;
    validate_journal(config, &directory, &saved)?;
    if fs::read_dir(&directory)?.count() != 1 {
        return Err(failure("unexpected transaction files"));
    }
    Ok(Some((directory, saved)))
}
fn validate_journal(config: &Path, directory: &Path, saved: &Journal) -> Result<()> {
    if saved.version != 1
        || saved.config != config
        || saved.files.len() != 5
        || saved.files[0].path != config
        || saved.trusted_before && saved.root_before.is_none()
    {
        return Err(failure("journal identity conflict"));
    }
    let paths: Vec<_> = saved.files.iter().map(|file| file.path.as_path()).collect();
    validate_paths(config, &paths, directory)?;
    for file in &saved.files {
        let identity = file.bytes.as_ref().map_or_else(|| "missing".into(), |bytes| digest(bytes));
        if !file.allowed.contains(&identity) || file.allowed.len() > 3 {
            return Err(failure("corrupt snapshot identity"));
        }
    }
    Ok(())
}
fn snapshot(path: &Path) -> Result<FileSnapshot> {
    authority::check_path(path)?;
    match fs::metadata(path) {
        Ok(meta) => {
            if !meta.is_file() || meta.len() > 4 * 1024 * 1024 {
                return Err(failure("invalid snapshot target"));
            }
            Ok(FileSnapshot {
                path: path.to_owned(),
                bytes: Some(fs::read(path)?),
                security: capture_security(path)?,
                allowed: vec![file_identity(path)?],
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(FileSnapshot {
            path: path.to_owned(),
            bytes: None,
            security: Vec::new(),
            allowed: vec!["missing".into()],
        }),
        Err(error) => Err(error.into()),
    }
}
fn file_identity(path: &Path) -> Result<String> {
    match fs::read(path) {
        Ok(bytes) => Ok(digest(&bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok("missing".into()),
        Err(error) => Err(error.into()),
    }
}
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}
fn allow_bytes(saved: &mut Journal, path: &Path, bytes: Option<&[u8]>) -> Result<()> {
    let entry =
        saved.files.iter_mut().find(|file| file.path == path).ok_or_else(|| failure("unknown journal target"))?;
    entry.allowed.push(bytes.map_or_else(|| "missing".into(), digest));
    Ok(())
}
fn validate_paths(config: &Path, paths: &[&Path], directory: &Path) -> Result<()> {
    use std::path::Component;
    if !config.is_absolute() {
        return Err(failure("absolute configuration path required"));
    }
    let mut identities = std::collections::BTreeSet::new();
    for path in paths {
        authority::check_path(path)?;
        if !path.is_absolute()
            || path.components().any(|part| matches!(part, Component::ParentDir | Component::CurDir))
            || path.starts_with(directory)
            || !identities.insert(path.to_string_lossy().to_lowercase())
        {
            return Err(failure("overlapping or non-absolute transaction paths"));
        }
    }
    Ok(())
}
fn begin(config_path: &Path, config: &AgentConfig) -> Result<(PathBuf, Journal)> {
    authority::require_system()?;
    authority::check_path(config_path)?;
    let directory = transaction_dir(config_path)?;
    if directory.try_exists()? {
        return Err(failure("unfinished transaction requires explicit rollback or commit"));
    }
    let backup = hosts_backup(&config.hosts_path);
    let paths = [config_path, &config.state_path, &config.hosts_path, &config.authority_path, &backup];
    validate_paths(config_path, &paths, &directory)?;
    let root_before = Authority::managed_root(&config.authority_path)?;
    let trusted_before = match &root_before {
        Some(root) => Machine.trusted(root)?,
        None => false,
    };
    let files = paths.iter().map(|path| snapshot(path)).collect::<Result<Vec<_>>>()?;
    // Do not repair an existing directory or weaken its ACL. Creation checks the trusted parent.
    Authority::prepare_directory(&directory)?;
    let saved = Journal {
        version: 1,
        config: config_path.to_owned(),
        files,
        root_active: root_before.clone(),
        root_before,
        trusted_before,
    };
    save(&directory, &saved)?;
    Ok((directory, saved))
}
fn hosts_backup(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".openems.bak");
    path.with_file_name(name)
}

/// Called after StopServices. Existing identity is preserved by provisioning.
pub fn prepare(
    config_path: &Path,
    bootstrap: Option<AgentConfig>,
    enable_http: bool,
    enable_https: bool,
    enable_dns: bool,
    enable_anti_bypass: bool,
) -> Result<()> {
    authority::require_system()?;
    if !config_path.is_absolute() {
        return Err(failure("absolute configuration path required"));
    }
    let parent = config_path.parent().ok_or_else(|| failure("missing configuration parent"))?;
    if !parent.try_exists()? && parent == crate::config::data_dir() {
        authority::check_path(parent)?;
        fs::create_dir_all(parent)?;
        crate::fsutil::secure_directory(parent)?;
    }
    let mut target = if config_path.try_exists()? {
        AgentConfig::from_file(config_path)?
    } else {
        bootstrap.clone().ok_or_else(|| failure("bootstrap configuration required"))?
    };
    target.block_page |= enable_http || enable_https;
    target.block_page_https |= enable_https;
    target.dns_filter |= enable_dns;
    target.anti_bypass |= enable_anti_bypass;
    // Reject impossible combinations (anti-bypass without DNS) before reserving ports or journaling.
    target.clone().validate()?;
    // Bind all requested listeners before touching config or trust. Handles remain reserved through preparation.
    let mut listeners = Vec::new();
    for (enabled, port) in
        [(target.block_page, target.block_page_port), (target.block_page_https, target.block_page_https_port)]
    {
        if enabled {
            listeners.push(
                TcpListener::bind((Ipv4Addr::LOCALHOST, port))
                    .map_err(|_| failure(&format!("loopback port {port} is unavailable")))?,
            );
        }
    }
    let mut resolvers = Vec::new();
    if target.dns_filter {
        let port = target.dns_port;
        let unavailable = |_| failure(&format!("loopback DNS port {port} is unavailable"));
        resolvers.push(UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).map_err(unavailable)?);
        listeners.push(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).map_err(unavailable)?);
    }
    let (directory, mut saved) = begin(config_path, &target)?;
    // Write-ahead expectation protects rollback against concurrent unrelated edits.
    let desired_config = match &saved.files[0].bytes {
        Some(bytes) => {
            let text = std::str::from_utf8(bytes).map_err(|_| failure("invalid configuration encoding"))?;
            let mut value: serde_json::Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
                .map_err(|_| failure("invalid configuration JSON"))?;
            value["block_page"] = target.block_page.into();
            value["block_page_https"] = target.block_page_https.into();
            // Must match provisioning byte for byte: the key appears only when enabled.
            if target.dns_filter {
                value["dns_filter"] = true.into();
            }
            if target.anti_bypass {
                value["anti_bypass"] = true.into();
            }
            serde_json::to_vec_pretty(&value).map_err(|_| failure("cannot encode planned configuration"))?
        }
        None => {
            serde_json::to_vec_pretty(&target.to_json()).map_err(|_| failure("cannot encode planned configuration"))?
        }
    };
    allow_bytes(&mut saved, config_path, Some(&desired_config))?;
    save(&directory, &saved)?;
    crate::provisioning::configure_install(
        config_path,
        bootstrap,
        enable_http,
        enable_https,
        enable_dns,
        enable_anti_bypass,
    )?;
    if target.block_page_https {
        let authority = Authority::load_or_create(&target.authority_path)?;
        saved.root_active = Some(authority.root_der().as_ref().to_vec());
        allow_bytes(&mut saved, &target.authority_path, Some(&fs::read(&target.authority_path)?))?;
        // Persist exact identity BEFORE the first trust mutation, including crash recovery.
        save(&directory, &saved)?;
        let root = saved.root_active.as_ref().ok_or_else(|| failure("missing active root"))?;
        if !Machine.trusted(root)? {
            Machine.trust(root)?;
        }
    }
    drop(listeners);
    drop(resolvers);
    Ok(())
}

/// Journal removal before exact root and hosts cleanup; MSI rollback can restore both.
pub fn prepare_removal(config_path: &Path) -> Result<()> {
    authority::require_system()?;
    if !config_path.try_exists()? {
        return Ok(());
    }
    let config = AgentConfig::from_file(config_path)?;
    let (directory, mut saved) = begin(config_path, &config)?;
    allow_bytes(&mut saved, &config.authority_path, None)?;
    if let Some(bytes) =
        saved.files.iter().find(|file| file.path == config.hosts_path).and_then(|file| file.bytes.as_ref())
    {
        let cleared = crate::hosts::replace_managed_block(bytes, b"")?;
        let bytes = bytes.clone();
        allow_bytes(&mut saved, &config.hosts_path, Some(&cleared))?;
        let backup_path = hosts_backup(&config.hosts_path);
        if let Some(original) = saved.files[4].bytes.as_ref() {
            let original = original.clone();
            if !original.is_empty() && !original.ends_with(b"\n") && cleared == [original.as_slice(), b"\n"].concat() {
                allow_bytes(&mut saved, &config.hosts_path, Some(&original))?;
            }
        } else if bytes != cleared {
            allow_bytes(&mut saved, &backup_path, Some(&bytes))?;
        }
    }
    save(&directory, &saved)?;
    if let Some(root) = Authority::managed_root(&config.authority_path)? {
        Machine.untrust(&root)?;
        fs::remove_file(&config.authority_path)?;
    }
    crate::hosts::clear_hosts(&config.hosts_path)?;
    // A graceful stop already removed the rule; this clears one left by a crash.
    if config.dns_filter {
        crate::nrpt::remove()?;
    }
    Ok(())
}

pub fn rollback(config_path: &Path) -> Result<()> {
    let Some((directory, saved)) = read(config_path)? else {
        return Ok(());
    };
    restore_transaction(&saved, &mut Machine)?;
    finish(&directory)
}
pub fn commit(config_path: &Path) -> Result<()> {
    let Some((directory, _)) = read(config_path)? else {
        return Ok(());
    };
    finish(&directory)
}
fn finish(directory: &Path) -> Result<()> {
    // Exact known files only: unexpected contents prevent cleanup instead of recursive deletion.
    fs::remove_file(directory.join("journal.json"))?;
    fs::remove_dir(directory)?;
    Ok(())
}

#[cfg(windows)]
fn capture_security(path: &Path) -> Result<Vec<u8>> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::GetFileSecurityW;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut needed = 0;
    // SAFETY: first call queries size; the second owns a sufficiently sized descriptor buffer.
    unsafe {
        GetFileSecurityW(wide.as_ptr(), 7, std::ptr::null_mut(), 0, &mut needed);
        if needed == 0 || needed > 65536 {
            return Err(failure("cannot capture file ACL"));
        }
        let mut bytes = vec![0u8; needed as usize];
        if GetFileSecurityW(wide.as_ptr(), 7, bytes.as_mut_ptr().cast(), needed, &mut needed) == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(bytes)
    }
}
#[cfg(windows)]
fn restore_security(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::{GetSecurityDescriptorControl, IsValidSecurityDescriptor, SetFileSecurityW};
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let descriptor = bytes.as_ptr().cast_mut().cast();
    let mut control = 0u16;
    let mut revision = 0;
    // SAFETY: persisted descriptor is trusted SYSTEM-only data; validate before using Windows APIs.
    unsafe {
        if bytes.len() < 20
            || IsValidSecurityDescriptor(descriptor) == 0
            || GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) == 0
        {
            return Err(failure("invalid saved ACL"));
        }
        let flags = 7 | if control & 0x1000 != 0 { 0x8000_0000 } else { 0x2000_0000 };
        if SetFileSecurityW(wide.as_ptr(), flags, descriptor) == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}
#[cfg(not(windows))]
fn capture_security(_: &Path) -> Result<Vec<u8>> {
    Err(failure("Windows required"))
}
#[cfg(not(windows))]
fn restore_security(_: &Path, _: &[u8]) -> Result<()> {
    Err(failure("Windows required"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[derive(Default)]
    struct Fake {
        roots: BTreeSet<Vec<u8>>,
        restored: bool,
        fail_restore: bool,
    }
    impl TransactionBackend for Fake {
        fn validate(&mut self, _: &[FileSnapshot]) -> Result<()> {
            Ok(())
        }
        fn trusted(&mut self, root: &[u8]) -> Result<bool> {
            Ok(self.roots.contains(root))
        }
        fn trust(&mut self, root: &[u8]) -> Result<()> {
            self.roots.insert(root.to_vec());
            Ok(())
        }
        fn untrust(&mut self, root: &[u8]) -> Result<()> {
            self.roots.remove(root);
            Ok(())
        }
        fn restore(&mut self, _: &[FileSnapshot]) -> Result<()> {
            if self.fail_restore {
                return Err(failure("restore failed"));
            }
            self.restored = true;
            Ok(())
        }
    }
    fn journal(before: Option<&[u8]>, trusted: bool, active: Option<&[u8]>) -> Journal {
        Journal {
            version: 1,
            config: "agent.json".into(),
            files: vec![],
            root_before: before.map(Vec::from),
            trusted_before: trusted,
            root_active: active.map(Vec::from),
        }
    }
    #[test]
    fn rollback_removes_only_new_root_and_preserves_unrelated_roots() {
        let mut backend = Fake::default();
        backend.roots.extend([b"ours".to_vec(), b"unrelated".to_vec()]);
        restore_transaction(&journal(None, false, Some(b"ours")), &mut backend).unwrap();
        assert_eq!(backend.roots, BTreeSet::from([b"unrelated".to_vec()]));
        assert!(backend.restored);
    }
    #[test]
    fn rollback_preserves_preexisting_trusted_authority() {
        let mut backend = Fake::default();
        backend.roots.insert(b"ours".to_vec());
        restore_transaction(&journal(Some(b"ours"), true, Some(b"ours")), &mut backend).unwrap();
        assert!(backend.roots.contains(b"ours".as_slice()));
    }
    #[test]
    fn rollback_removes_new_trust_for_existing_untrusted_authority() {
        let mut backend = Fake::default();
        backend.roots.insert(b"ours".to_vec());
        restore_transaction(&journal(Some(b"ours"), false, Some(b"ours")), &mut backend).unwrap();
        assert!(backend.roots.is_empty());
        assert!(backend.restored);
    }
    #[test]
    fn uninstall_rollback_restores_existing_root_and_is_repeatable() {
        let mut backend = Fake::default();
        let saved = journal(Some(b"ours"), true, Some(b"ours"));
        restore_transaction(&saved, &mut backend).unwrap();
        restore_transaction(&saved, &mut backend).unwrap();
        assert_eq!(backend.roots, BTreeSet::from([b"ours".to_vec()]));
    }
    #[test]
    fn restore_failure_is_reported_for_retry() {
        let mut backend = Fake { fail_restore: true, ..Fake::default() };
        assert!(restore_transaction(&journal(None, false, None), &mut backend).is_err());
    }

    #[test]
    fn external_file_edits_are_detected_before_rollback_mutates_anything() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("state.json");
        fs::write(&path, b"previous").unwrap();
        let mut entry = snapshot(&path).unwrap();
        entry.allowed.push(digest(b"installer change"));
        fs::write(&path, b"unrelated later change").unwrap();
        assert!(Machine.validate(&[entry]).is_err());
        assert_eq!(fs::read(path).unwrap(), b"unrelated later change");
    }

    #[test]
    fn overlapping_or_relative_paths_are_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        let config = temporary.path().join("agent.json");
        let directory = temporary.path().join("installer-transaction");
        assert!(validate_paths(&config, &[&config, &config], &directory).is_err());
        assert!(validate_paths(&config, &[Path::new("relative.json")], &directory).is_err());
        assert!(validate_paths(&config, &[&directory.join("journal.json")], &directory).is_err());
    }

    #[test]
    fn unsupported_or_inconsistent_journal_identity_is_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        let config = temporary.path().join("agent.json");
        let directory = temporary.path().join("installer-transaction");
        let mut saved = journal(None, false, None);
        saved.config = config.clone();
        saved.files = ["agent.json", "state.json", "hosts", "authority.json", "hosts.openems.bak"]
            .iter()
            .map(|name| snapshot(&temporary.path().join(name)).unwrap())
            .collect();
        validate_journal(&config, &directory, &saved).unwrap();
        saved.version = 2;
        assert!(validate_journal(&config, &directory, &saved).is_err());
        saved.version = 1;
        saved.trusted_before = true;
        assert!(validate_journal(&config, &directory, &saved).is_err());
        saved.trusted_before = false;
        saved.files[0].allowed.clear();
        assert!(validate_journal(&config, &directory, &saved).is_err());
    }
}
