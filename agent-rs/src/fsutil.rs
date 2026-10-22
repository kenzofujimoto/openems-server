//! Crash-safe file replacement shared by the hosts file and endpoint state.

use crate::error::{AgentError, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

fn temp_path(path: &Path) -> PathBuf {
    let name = format!(".openems-{:016x}.tmp", fastrand::u64(..));
    path.parent().map_or_else(|| PathBuf::from(&name), |parent| parent.join(&name))
}

/// Write `data` to a sibling temp file and rename it over `path`.
/// With `expected`, refuse when someone changed the file since it was read.
pub fn atomic_write(path: &Path, data: &[u8], expected: Option<&[u8]>, private: bool) -> Result<()> {
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let temp = temp_path(path);
    let outcome = (|| -> Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&temp)?;
        if private {
            secure_file(&temp)?;
        } else if let Ok(metadata) = fs::metadata(path) {
            fs::set_permissions(&temp, metadata.permissions())?;
        }
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        if let Some(expected) = expected {
            let current = match fs::read(path) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(error) => return Err(error.into()),
            };
            if current != expected {
                return Err(AgentError::Local("file changed concurrently; retry required".into()));
            }
        }
        fs::rename(&temp, path)?;
        Ok(())
    })();
    if outcome.is_err() {
        let _ = fs::remove_file(&temp);
    }
    outcome
}

/// Protect secret files before their first write: owner, SYSTEM and Administrators only.
#[cfg(windows)]
pub fn secure_file(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SetFileSecurityW};

    // OWNER RIGHTS, SYSTEM and BUILTIN\Administrators; protected DACL blocks inheritance.
    let sddl: Vec<u16> = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)".encode_utf16().chain([0]).collect();
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: both strings are NUL-terminated and outlive the calls; the
    // descriptor allocated by Windows is released with LocalFree below.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut descriptor, std::ptr::null_mut())
            == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let applied = SetFileSecurityW(wide.as_ptr(), 0x8000_0004, descriptor);
        let error = std::io::Error::last_os_error();
        LocalFree(descriptor as HLOCAL);
        if applied == 0 {
            return Err(error.into());
        }
    }
    Ok(())
}

/// Lock the service data folder: Administrators own it, SYSTEM and Administrators
/// write, users only read. Requires elevation; used for the default location.
#[cfg(windows)]
pub fn secure_directory(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SetFileSecurityW};

    let sddl: Vec<u16> =
        "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)".encode_utf16().chain([0]).collect();
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: NUL-terminated buffers outlive the calls; LocalFree releases the descriptor.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut descriptor, std::ptr::null_mut())
            == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        // OWNER | DACL | PROTECTED_DACL
        let applied = SetFileSecurityW(wide.as_ptr(), 0x8000_0005, descriptor);
        let error = std::io::Error::last_os_error();
        LocalFree(descriptor as HLOCAL);
        if applied == 0 {
            return Err(error.into());
        }
    }
    Ok(())
}

#[cfg(unix)]
pub fn secure_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(unix)]
pub fn secure_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Read a UTF-8 text file, tolerating the BOM that Windows editors add.
pub fn read_text_without_bom(path: &Path) -> Result<String> {
    let bytes = fs::read(path)?;
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
    String::from_utf8(bytes.to_vec()).map_err(|_| AgentError::Local("file is not valid UTF-8".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_files_and_detects_concurrent_edits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        atomic_write(&path, b"first", None, false).unwrap();
        atomic_write(&path, b"second", Some(b"first"), false).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert!(atomic_write(&path, b"third", Some(b"stale"), false).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"second");
        let leftovers = fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(leftovers, 1, "temporary files are cleaned up");
    }

    #[test]
    fn private_files_are_written_and_bom_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        atomic_write(&path, b"\xef\xbb\xbf{}", None, true).unwrap();
        assert_eq!(read_text_without_bom(&path).unwrap(), "{}");
    }
}
