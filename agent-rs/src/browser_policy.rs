//! Browser DoH policies under HKLM\SOFTWARE\Policies. Values that existed before the agent are
//! saved once, before the first write, and restored at uninstall unless someone changed them since.
use crate::error::{AgentError, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RegValue {
    Text(String),
    Dword(u32),
    /// Any other registry type, kept byte for byte so a restore is exact.
    Raw {
        kind: u32,
        data: Vec<u8>,
    },
}

pub struct Setting {
    pub key: &'static str,
    pub name: &'static str,
    text: Option<&'static str>,
    dword: u32,
}

impl Setting {
    pub fn value(&self) -> RegValue {
        self.text.map_or(RegValue::Dword(self.dword), |text| RegValue::Text(text.to_owned()))
    }

    fn id(&self) -> String {
        format!(r"{}\{}", self.key, self.name)
    }
}

const fn text(key: &'static str, name: &'static str, value: &'static str) -> Setting {
    Setting { key, name, text: Some(value), dword: 0 }
}

const fn dword(key: &'static str, name: &'static str, value: u32) -> Setting {
    Setting { key, name, text: None, dword: value }
}

/// Chrome and Edge: DoH off. Firefox: DoH off and locked, and trust the machine roots (the agent CA).
pub const SETTINGS: [Setting; 5] = [
    text(r"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode", "off"),
    text(r"SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode", "off"),
    dword(r"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Enabled", 0),
    dword(r"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Locked", 1),
    dword(r"SOFTWARE\Policies\Mozilla\Firefox\Certificates", "ImportEnterpriseRoots", 1),
];

/// HKLM access; tests use a simulated store.
pub trait Registry {
    fn get(&mut self, key: &str, name: &str) -> Result<Option<RegValue>>;
    fn set(&mut self, key: &str, name: &str, value: &RegValue) -> Result<()>;
    fn delete(&mut self, key: &str, name: &str) -> Result<()>;
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Original {
    key: String,
    name: String,
    value: Option<RegValue>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    version: u8,
    originals: Vec<Original>,
}

fn load(path: &Path) -> Result<Saved> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Saved { version: 1, originals: Vec::new() });
        }
        Err(error) => return Err(error.into()),
    };
    let saved: Saved = serde_json::from_slice(&bytes)
        .ok()
        .filter(|saved: &Saved| saved.version == 1 && bytes.len() <= 64 * 1024)
        .ok_or_else(|| AgentError::State("browser policy originals are unreadable; restore them manually".into()))?;
    Ok(saved)
}

fn store(path: &Path, saved: &Saved) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(saved).map_err(|error| AgentError::Local(error.to_string()))?;
    crate::fsutil::atomic_write(path, &bytes, None, true)
}

/// Apply every setting that differs; returns the ones written (empty when already applied).
pub fn ensure(registry: &mut impl Registry, originals: &Path) -> Result<Vec<String>> {
    let mut saved = load(originals)?;
    let mut pending = Vec::new();
    for setting in &SETTINGS {
        let current = registry.get(setting.key, setting.name)?;
        if current.as_ref() == Some(&setting.value()) {
            continue;
        }
        // Only the first difference is the true original; later ones are tampering.
        if !saved.originals.iter().any(|original| original.key == setting.key && original.name == setting.name) {
            saved.originals.push(Original { key: setting.key.into(), name: setting.name.into(), value: current });
        }
        pending.push(setting);
    }
    if pending.is_empty() {
        return Ok(Vec::new());
    }
    // Write-ahead: a crash after any registry write still knows what to restore.
    store(originals, &saved)?;
    let mut changed = Vec::with_capacity(pending.len());
    for setting in pending {
        registry.set(setting.key, setting.name, &setting.value())?;
        changed.push(setting.id());
    }
    Ok(changed)
}

/// Put back the pre-agent values that still hold the agent's setting, then forget the originals.
pub fn restore(registry: &mut impl Registry, originals: &Path) -> Result<()> {
    if !originals.try_exists()? {
        return Ok(());
    }
    let saved = load(originals)?;
    for original in &saved.originals {
        let Some(setting) =
            SETTINGS.iter().find(|setting| setting.key == original.key && setting.name == original.name)
        else {
            continue;
        };
        if registry.get(setting.key, setting.name)?.as_ref() != Some(&setting.value()) {
            continue;
        }
        match &original.value {
            Some(value) => registry.set(setting.key, setting.name, value)?,
            None => registry.delete(setting.key, setting.name)?,
        }
    }
    std::fs::remove_file(originals)?;
    Ok(())
}

#[cfg(windows)]
pub use machine::WindowsRegistry;

#[cfg(windows)]
mod machine {
    use super::{RegValue, Registry};
    use crate::error::{AgentError, Result};
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_DWORD, REG_OPTION_NON_VOLATILE,
        REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    };

    /// HKLM in the 64-bit view.
    pub struct WindowsRegistry;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

    fn failure(operation: &str, key: &str, code: u32) -> AgentError {
        AgentError::Local(format!("registry {operation} failed for {key} ({code})"))
    }

    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful open/create and is closed once.
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn open(key: &str, access: u32) -> Result<Option<Key>> {
        let mut handle: HKEY = std::ptr::null_mut();
        // SAFETY: valid NUL-terminated subkey and out pointer.
        let status =
            unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, wide(key).as_ptr(), 0, access | KEY_WOW64_64KEY, &mut handle) };
        match status {
            ERROR_SUCCESS => Ok(Some(Key(handle))),
            ERROR_FILE_NOT_FOUND => Ok(None),
            code => Err(failure("open", key, code)),
        }
    }

    impl Registry for WindowsRegistry {
        fn get(&mut self, key: &str, name: &str) -> Result<Option<RegValue>> {
            let Some(handle) = open(key, KEY_QUERY_VALUE)? else { return Ok(None) };
            let name_w = wide(name);
            let (mut kind, mut size) = (0u32, 0u32);
            // SAFETY: size query with null data, then a buffer of the reported size.
            let status = unsafe {
                RegQueryValueExW(
                    handle.0,
                    name_w.as_ptr(),
                    std::ptr::null(),
                    &mut kind,
                    std::ptr::null_mut(),
                    &mut size,
                )
            };
            match status {
                ERROR_SUCCESS => {}
                ERROR_FILE_NOT_FOUND => return Ok(None),
                code => return Err(failure("query", key, code)),
            }
            if size > 64 * 1024 {
                return Err(failure("query", key, size));
            }
            let mut data = vec![0u8; size as usize];
            // SAFETY: `data` holds `size` bytes.
            let status = unsafe {
                RegQueryValueExW(handle.0, name_w.as_ptr(), std::ptr::null(), &mut kind, data.as_mut_ptr(), &mut size)
            };
            if status != ERROR_SUCCESS {
                return Err(failure("query", key, status));
            }
            data.truncate(size as usize);
            Ok(Some(match kind {
                REG_SZ => {
                    let units: Vec<u16> =
                        data.as_chunks::<2>().0.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
                    RegValue::Text(String::from_utf16_lossy(&units).trim_end_matches('\0').to_owned())
                }
                REG_DWORD if data.len() == 4 => {
                    RegValue::Dword(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
                }
                _ => RegValue::Raw { kind, data },
            }))
        }

        fn set(&mut self, key: &str, name: &str, value: &RegValue) -> Result<()> {
            let mut handle: HKEY = std::ptr::null_mut();
            // SAFETY: valid subkey, no class or security attributes, out pointer for the handle.
            let status = unsafe {
                RegCreateKeyExW(
                    HKEY_LOCAL_MACHINE,
                    wide(key).as_ptr(),
                    0,
                    std::ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_SET_VALUE | KEY_WOW64_64KEY,
                    std::ptr::null(),
                    &mut handle,
                    std::ptr::null_mut(),
                )
            };
            if status != ERROR_SUCCESS {
                return Err(failure("create", key, status));
            }
            let handle = Key(handle);
            let (kind, data): (u32, Vec<u8>) = match value {
                RegValue::Text(text) => (REG_SZ, wide(text).iter().flat_map(|unit| unit.to_le_bytes()).collect()),
                RegValue::Dword(number) => (REG_DWORD, number.to_le_bytes().to_vec()),
                RegValue::Raw { kind, data } => (*kind, data.clone()),
            };
            let length = u32::try_from(data.len()).map_err(|_| failure("set", key, 0))?;
            // SAFETY: `data` holds `length` bytes of the declared type.
            let status = unsafe { RegSetValueExW(handle.0, wide(name).as_ptr(), 0, kind, data.as_ptr(), length) };
            if status != ERROR_SUCCESS {
                return Err(failure("set", key, status));
            }
            Ok(())
        }

        fn delete(&mut self, key: &str, name: &str) -> Result<()> {
            let Some(handle) = open(key, KEY_SET_VALUE)? else { return Ok(()) };
            // SAFETY: open handle and NUL-terminated value name.
            match unsafe { RegDeleteValueW(handle.0, wide(name).as_ptr()) } {
                ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
                code => Err(failure("delete", key, code)),
            }
        }
    }
}
