//! Machine-local issuing authority. Private material never leaves this module.
use crate::error::{AgentError, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::Path, sync::Arc};

fn failure() -> AgentError {
    AgentError::Local("local certificate authority operation failed".into())
}

pub struct Authority {
    issuer: Issuer<'static, KeyPair>,
    root: CertificateDer<'static>,
}
impl Authority {
    fn generate() -> Result<(Self, Vec<u8>)> {
        let key = KeyPair::generate().map_err(|_| failure())?;
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, format!("OpenEMS local block page {:016x}", fastrand::u64(..)));
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + time::Duration::days(365);
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = params.self_signed(&key).map_err(|_| failure())?;
        let root = cert.der().clone();
        let secret = key.serialize_der();
        Ok((Self { issuer: Issuer::new(params, key), root }, secret))
    }
    /// Ephemeral CA for isolated TLS validation. Does not modify persistence or trust.
    pub fn ephemeral() -> Result<Self> {
        let (ca, mut secret) = Self::generate()?;
        secret.fill(0);
        Ok(ca)
    }
    pub fn prepare_directory(path: &Path) -> Result<()> {
        require_system()?;
        check_path(path)?;
        verify_parent_directory(path.parent().ok_or_else(failure)?)?;
        if path.exists() {
            return verify_authority_file(path);
        }
        fs::create_dir(path)?;
        secure_authority_file(path)?;
        verify_authority_file(path)
    }
    pub fn load_existing(path: &Path) -> Result<Self> {
        require_system()?;
        verify_authority_file(path)?;
        Self::load_or_create(path)
    }
    /// Exact managed root without decrypting the private key or requiring an unexpired issuer.
    pub(crate) fn managed_root(path: &Path) -> Result<Option<Vec<u8>>> {
        require_system()?;
        check_path(path)?;
        if !path.try_exists()? {
            return Ok(None);
        }
        verify_authority_file(path)?;
        if fs::metadata(path)?.len() > 65536 {
            return Err(failure());
        }
        let saved: Saved = serde_json::from_slice(&fs::read(path)?).map_err(|_| failure())?;
        use x509_parser::prelude::FromDer;
        let (rest, cert) = x509_parser::certificate::X509Certificate::from_der(&saved.root).map_err(|_| failure())?;
        if saved.version != 1 || !rest.is_empty() || !cert.is_ca() {
            return Err(failure());
        }
        Ok(Some(saved.root))
    }
    /// Removes only the exact root recorded in the protected authority file.
    /// Expired roots and unreadable private keys remain removable.
    pub fn remove_managed_trust(path: &Path, store: &mut impl TrustStore) -> Result<()> {
        require_system()?;
        check_path(path)?;
        if !path.exists() {
            return Ok(());
        }
        verify_authority_file(path)?;
        if fs::metadata(path)?.len() > 65536 {
            return Err(failure());
        }
        let saved: Saved = serde_json::from_slice(&fs::read(path)?).map_err(|_| failure())?;
        if saved.version != 1 {
            return Err(failure());
        }
        use x509_parser::prelude::FromDer;
        let (rest, cert) = x509_parser::certificate::X509Certificate::from_der(&saved.root).map_err(|_| failure())?;
        if !rest.is_empty() || !cert.is_ca() {
            return Err(failure());
        }
        store.remove(&saved.root)?;
        fs::remove_file(path)?;
        Ok(())
    }
    pub fn load_or_create(path: &Path) -> Result<Self> {
        require_system()?;
        let directory = path.parent().ok_or_else(failure)?;
        Self::prepare_directory(directory)?;
        if path.exists() {
            verify_authority_file(path)?;
        }
        Self::load_with(path, protect, unprotect, secure_authority_file)
    }
    fn load_with(
        path: &Path,
        encrypt: impl Fn(&[u8]) -> Result<Vec<u8>>,
        decrypt: impl Fn(&[u8]) -> Result<Vec<u8>>,
        secure: impl Fn(&Path) -> Result<()>,
    ) -> Result<Self> {
        check_path(path)?;
        if let Ok(meta) = fs::metadata(path)
            && meta.len() > 65536
        {
            return Err(failure());
        }
        match fs::read(path) {
            Ok(bytes) => {
                let saved: Saved = serde_json::from_slice(&bytes).map_err(|_| failure())?;
                if saved.version != 1 {
                    return Err(failure());
                }
                let mut secret = decrypt(&saved.protected_key)?;
                let key = KeyPair::try_from(secret.as_slice()).map_err(|_| failure());
                secret.fill(0);
                let key = key?;
                let root = CertificateDer::from(saved.root);
                use x509_parser::prelude::FromDer;
                let (_, parsed) =
                    x509_parser::certificate::X509Certificate::from_der(root.as_ref()).map_err(|_| failure())?;
                let constraints = parsed.basic_constraints().map_err(|_| failure())?.ok_or_else(failure)?;
                let usages = parsed.key_usage().map_err(|_| failure())?.ok_or_else(failure)?;
                if !parsed.validity().is_valid()
                    || !constraints.value.ca
                    || constraints.value.path_len_constraint != Some(0)
                    || usages.value.flags != 0x60
                    || parsed.subject() != parsed.issuer()
                {
                    return Err(failure());
                }
                let issuer = Issuer::from_ca_cert_der(&root, key).map_err(|_| failure())?;
                let ca = Self { issuer, root };
                // Validate issuer key, CA constraints and validity before trusting persisted state.
                let probe = ca.issue("authority-validation.invalid")?;
                let mut roots = rustls::RootCertStore::empty();
                roots.add(ca.root_der()).map_err(|_| failure())?;
                let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
                    Arc::new(roots),
                    Arc::new(rustls::crypto::ring::default_provider()),
                )
                .build()
                .map_err(|_| failure())?;
                use rustls::client::danger::ServerCertVerifier;
                verifier
                    .verify_server_cert(
                        &probe.cert[0],
                        &[],
                        &rustls::pki_types::ServerName::try_from("authority-validation.invalid")
                            .map_err(|_| failure())?,
                        &[],
                        rustls::pki_types::UnixTime::now(),
                    )
                    .map_err(|_| failure())?;
                Ok(ca)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let (ca, mut secret) = Self::generate()?;
                let protected = encrypt(&secret);
                secret.fill(0);
                let saved = Saved { version: 1, root: ca.root.to_vec(), protected_key: protected? };
                let bytes = serde_json::to_vec(&saved).map_err(|_| failure())?;
                // create_new prevents replacing another authority in a race.
                let mut file = fs::OpenOptions::new().write(true).create_new(true).open(path)?;
                let outcome: Result<()> = (|| {
                    secure(path)?;
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                    Ok(())
                })();
                if outcome.is_err() {
                    drop(file);
                    fs::remove_file(path)
                        .map_err(|_| AgentError::Local("authority creation failed and file rollback failed".into()))?;
                }
                outcome?;
                Ok(ca)
            }
            Err(e) => Err(e.into()),
        }
    }
    pub fn root_der(&self) -> CertificateDer<'static> {
        self.root.clone()
    }
    pub fn fingerprint(&self) -> String {
        hex::encode(Sha256::digest(self.root.as_ref()))
    }
    /// Caller must authorize the domain against the current blocking policy first.
    pub fn issue(&self, domain: &str) -> Result<Arc<CertifiedKey>> {
        validate_domain(domain)?;
        let key = KeyPair::generate().map_err(|_| failure())?;
        let mut params = CertificateParams::new(vec![domain.to_owned()]).map_err(|_| failure())?;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        // Certificates only survive a single day; the authority is never exported.
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_| failure())?.as_secs() as i64;
        params.not_before = time::OffsetDateTime::from_unix_timestamp(now - 300).map_err(|_| failure())?;
        use x509_parser::prelude::FromDer;
        let (_, root) =
            x509_parser::certificate::X509Certificate::from_der(self.root.as_ref()).map_err(|_| failure())?;
        if !root.validity().is_valid() {
            return Err(failure());
        }
        params.not_after =
            time::OffsetDateTime::from_unix_timestamp((now + 86100).min(root.validity().not_after.timestamp()))
                .map_err(|_| failure())?;
        let cert = params.signed_by(&key, &self.issuer).map_err(|_| failure())?;
        let signing =
            rustls::crypto::ring::sign::any_supported_type(&PrivatePkcs8KeyDer::from(key.serialize_der()).into())
                .map_err(|_| failure())?;
        Ok(Arc::new(CertifiedKey::new(vec![cert.der().clone()], signing)))
    }
}

fn validate_domain(domain: &str) -> Result<()> {
    if domain.len() > 253
        || !domain.contains('.')
        || domain.parse::<std::net::IpAddr>().is_ok()
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
    {
        return Err(failure());
    }
    Ok(())
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    version: u8,
    root: Vec<u8>,
    protected_key: Vec<u8>,
}
pub(crate) fn check_path(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        if let Ok(meta) = fs::symlink_metadata(ancestor) {
            if meta.file_type().is_symlink() {
                return Err(failure());
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if meta.file_attributes() & 0x400 != 0 {
                    return Err(failure());
                }
            }
        }
    }
    Ok(())
}
#[cfg(not(windows))]
fn protect(_: &[u8]) -> Result<Vec<u8>> {
    Err(AgentError::Local("persistent local authority requires Windows DPAPI".into()))
}
#[cfg(not(windows))]
fn unprotect(_: &[u8]) -> Result<Vec<u8>> {
    Err(failure())
}
#[cfg(not(windows))]
pub(crate) fn secure_authority_file(path: &Path) -> Result<()> {
    crate::fsutil::secure_file(path)
}
#[cfg(windows)]
fn protect(data: &[u8]) -> Result<Vec<u8>> {
    crypt(data, true)
}
#[cfg(windows)]
fn unprotect(data: &[u8]) -> Result<Vec<u8>> {
    crypt(data, false)
}
#[cfg(windows)]
fn crypt(data: &[u8], encrypt: bool) -> Result<Vec<u8>> {
    use windows_sys::Win32::{Foundation::LocalFree, Security::Cryptography::*};
    let input =
        CRYPT_INTEGER_BLOB { cbData: data.len().try_into().map_err(|_| failure())?, pbData: data.as_ptr() as *mut u8 };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    // SAFETY: buffers are valid for the call; DPAPI allocation is freed and zeroed.
    unsafe {
        let ok = if encrypt {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(failure());
        }
        let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
        LocalFree(output.pbData as _);
        Ok(result)
    }
}
#[cfg(windows)]
pub(crate) fn secure_authority_file(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW, PSECURITY_DESCRIPTOR, SetFileSecurityW,
        },
    };
    let sddl: Vec<u16> = "D:P(A;;FA;;;SY)".encode_utf16().chain([0]).collect();
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: NUL terminated buffers outlive Windows calls.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut descriptor, std::ptr::null_mut())
            == 0
        {
            return Err(failure());
        }
        let ok = SetFileSecurityW(wide.as_ptr(), 0x8000_0004, descriptor);
        LocalFree(descriptor as _);
        if ok == 0 {
            return Err(failure());
        }
    }
    Ok(())
}

/// Stores must identify entries by exact DER, never by the display name.
pub trait TrustStore {
    fn contains(&mut self, der: &[u8]) -> Result<bool>;
    fn add(&mut self, der: &[u8]) -> Result<()>;
    fn remove(&mut self, der: &[u8]) -> Result<()>;
}
impl Authority {
    /// Roll back this exact newly installed root if the subsequent action fails.
    pub fn install_with<T>(&self, store: &mut impl TrustStore, after_install: impl FnOnce() -> Result<T>) -> Result<T> {
        let existed = store.contains(self.root.as_ref())?;
        if !existed {
            store.add(self.root.as_ref())?;
        }
        match after_install() {
            Ok(value) => Ok(value),
            Err(error) => {
                if !existed {
                    store
                        .remove(self.root.as_ref())
                        .map_err(|_| AgentError::Local("trust installation failed and root rollback failed".into()))?;
                }
                Err(error)
            }
        }
    }
    pub fn remove_trust(&self, store: &mut impl TrustStore) -> Result<()> {
        store.remove(self.root.as_ref())
    }
}

/// Explicit LocalMachine ROOT lifecycle; constructing this does not open or mutate a store.
#[cfg(windows)]
pub struct WindowsTrustStore;
#[cfg(windows)]
impl WindowsTrustStore {
    fn with_store<T>(
        action: impl FnOnce(windows_sys::Win32::Security::Cryptography::HCERTSTORE) -> Result<T>,
    ) -> Result<T> {
        use windows_sys::Win32::Security::Cryptography::*;
        let name: Vec<u16> = "ROOT".encode_utf16().chain([0]).collect();
        // SAFETY: store name is valid; handle is always closed after action.
        unsafe {
            let store = CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                0,
                0,
                CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG,
                name.as_ptr() as _,
            );
            if store.is_null() {
                return Err(failure());
            }
            let result = action(store);
            let closed = CertCloseStore(store, 0);
            if closed == 0 {
                return Err(failure());
            }
            result
        }
    }
}
#[cfg(windows)]
impl TrustStore for WindowsTrustStore {
    fn contains(&mut self, der: &[u8]) -> Result<bool> {
        use windows_sys::Win32::Security::Cryptography::*;
        Self::with_store(|store| {
            // SAFETY: enumeration owns contexts, consuming previous on each call.
            unsafe {
                let mut context = CertEnumCertificatesInStore(store, std::ptr::null());
                while !context.is_null() {
                    let bytes = std::slice::from_raw_parts((*context).pbCertEncoded, (*context).cbCertEncoded as usize);
                    if bytes == der {
                        CertFreeCertificateContext(context);
                        return Ok(true);
                    }
                    context = CertEnumCertificatesInStore(store, context);
                }
            }
            Ok(false)
        })
    }
    fn add(&mut self, der: &[u8]) -> Result<()> {
        use windows_sys::Win32::Security::Cryptography::*;
        Self::with_store(|store| {
            // SAFETY: DER slice outlives the function, output context not requested.
            unsafe {
                if CertAddEncodedCertificateToStore(
                    store,
                    X509_ASN_ENCODING,
                    der.as_ptr(),
                    der.len().try_into().map_err(|_| failure())?,
                    CERT_STORE_ADD_NEW,
                    std::ptr::null_mut(),
                ) == 0
                {
                    return Err(failure());
                }
            }
            Ok(())
        })
    }
    fn remove(&mut self, der: &[u8]) -> Result<()> {
        use windows_sys::Win32::Security::Cryptography::*;
        Self::with_store(|store| {
            // SAFETY: deletion consumes matching context; no name-based broad deletion.
            unsafe {
                let mut context = CertEnumCertificatesInStore(store, std::ptr::null());
                while !context.is_null() {
                    let bytes = std::slice::from_raw_parts((*context).pbCertEncoded, (*context).cbCertEncoded as usize);
                    if bytes == der {
                        if CertDeleteCertificateFromStore(context) == 0 {
                            return Err(failure());
                        }
                        return Ok(());
                    }
                    context = CertEnumCertificatesInStore(store, context);
                }
            }
            Ok(())
        })
    }
}

#[cfg(not(windows))]
pub(crate) fn require_system() -> Result<()> {
    Err(AgentError::Local("persistent local authority requires Windows SYSTEM".into()))
}
#[cfg(not(windows))]
pub(crate) fn verify_authority_file(_: &Path) -> Result<()> {
    Err(failure())
}
#[cfg(windows)]
pub(crate) fn require_system() -> Result<()> {
    use windows_sys::Win32::Security::*;
    let mut buffer = [0usize; 128];
    let mut length = 0;
    // SAFETY: -4 is Windows current-process token pseudo-handle, valid without closing;
    // aligned buffer exceeds TOKEN_USER and maximum SID length.
    unsafe {
        if GetTokenInformation(
            -4isize as _,
            TokenUser,
            buffer.as_mut_ptr() as _,
            std::mem::size_of_val(&buffer) as u32,
            &mut length,
        ) == 0
        {
            return Err(failure());
        }
        let user = &*(buffer.as_ptr() as *const TOKEN_USER);
        if IsWellKnownSid(user.User.Sid, WinLocalSystemSid) == 0 {
            return Err(AgentError::Local("persistent local authority requires Windows SYSTEM".into()));
        }
    }
    Ok(())
}
#[cfg(windows)]
pub(crate) fn verify_authority_file(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{Authorization::*, *},
    };
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut owner: PSID = std::ptr::null_mut();
    let mut acl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: allocated descriptor owns owner/DACL pointers until freed below.
    unsafe {
        if GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut acl,
            std::ptr::null_mut(),
            &mut sd,
        ) != 0
        {
            return Err(failure());
        }
        let valid = (|| {
            let mut control = 0u16;
            let mut revision = 0;
            if GetSecurityDescriptorControl(sd, &mut control, &mut revision) == 0 || control & 0x1000 == 0 {
                return false;
            }
            if owner.is_null() || IsWellKnownSid(owner, WinLocalSystemSid) == 0 || acl.is_null() || (*acl).AceCount != 1
            {
                return false;
            }
            let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
            if GetAce(acl, 0, &mut ace) == 0 {
                return false;
            }
            let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
            allowed.Header.AceType == 0
                && allowed.Header.AceFlags == 0
                && IsWellKnownSid((&allowed.SidStart as *const u32).cast_mut().cast(), WinLocalSystemSid) != 0
        })();
        LocalFree(sd as _);
        if !valid {
            return Err(failure());
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn verify_parent_directory(_: &Path) -> Result<()> {
    Err(failure())
}
#[cfg(windows)]
fn verify_parent_directory(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{Authorization::*, *},
    };
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut owner: PSID = std::ptr::null_mut();
    let mut acl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: security descriptor owns SID/ACL memory through validation.
    unsafe {
        if GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut acl,
            std::ptr::null_mut(),
            &mut sd,
        ) != 0
        {
            return Err(failure());
        }
        let trusted = |sid: PSID| {
            !sid.is_null()
                && (IsWellKnownSid(sid, WinLocalSystemSid) != 0
                    || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0)
        };
        let valid = (|| {
            if !trusted(owner) || acl.is_null() {
                return false;
            }
            for index in 0..(*acl).AceCount {
                let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
                if GetAce(acl, index.into(), &mut ace) == 0 {
                    return false;
                }
                let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
                if allowed.Header.AceType == 1 {
                    continue;
                }
                if allowed.Header.AceType != 0 {
                    return false;
                }
                if allowed.Mask & 0x500d0156 != 0 && !trusted((&allowed.SidStart as *const u32).cast_mut().cast()) {
                    return false;
                }
            }
            true
        })();
        LocalFree(sd as _);
        if !valid {
            return Err(failure());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    #[derive(Default)]
    struct MemoryStore {
        roots: BTreeSet<Vec<u8>>,
    }
    impl TrustStore for MemoryStore {
        fn contains(&mut self, der: &[u8]) -> Result<bool> {
            Ok(self.roots.contains(der))
        }
        fn add(&mut self, der: &[u8]) -> Result<()> {
            self.roots.insert(der.to_vec());
            Ok(())
        }
        fn remove(&mut self, der: &[u8]) -> Result<()> {
            self.roots.remove(der);
            Ok(())
        }
    }
    #[test]
    fn rollback_only_removes_new_owned_root() {
        let ca = Authority::ephemeral().unwrap();
        let other = Authority::ephemeral().unwrap();
        let mut store = MemoryStore::default();
        store.add(other.root_der().as_ref()).unwrap();
        assert!(ca.install_with(&mut store, || Err::<(), _>(failure())).is_err());
        assert!(!store.contains(ca.root_der().as_ref()).unwrap());
        assert!(store.contains(other.root_der().as_ref()).unwrap());
        ca.install_with(&mut store, || Ok(())).unwrap();
        assert!(ca.install_with(&mut store, || Err::<(), _>(failure())).is_err());
        assert!(store.contains(ca.root_der().as_ref()).unwrap());
        ca.remove_trust(&mut store).unwrap();
        assert!(store.contains(other.root_der().as_ref()).unwrap());
    }
    #[test]
    fn mock_encrypted_store_reuses_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.json");
        // Inject a mock protector: disk stores only opaque bytes. Key stays in test memory.
        let secret = std::cell::RefCell::new(Vec::new());
        let encrypt = |bytes: &[u8]| {
            *secret.borrow_mut() = bytes.to_vec();
            Ok(b"opaque-encrypted-key".to_vec())
        };
        let decrypt = |bytes: &[u8]| {
            if bytes == b"opaque-encrypted-key" { Ok(secret.borrow().clone()) } else { Err(failure()) }
        };
        let ca = Authority::load_with(&path, encrypt, decrypt, |_| Ok(())).unwrap();
        let again = Authority::load_with(&path, encrypt, decrypt, |_| Ok(())).unwrap();
        assert_eq!(ca.fingerprint(), again.fingerprint());
        assert!(!fs::read(&path).unwrap().windows(secret.borrow().len()).any(|b| b == secret.borrow().as_slice()));
        assert!(Authority::load_with(&path, encrypt, |_| Err(failure()), |_| Ok(())).is_err());
        let mut saved: Saved = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        saved.root = Authority::ephemeral().unwrap().root_der().to_vec();
        fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
        assert!(Authority::load_with(&path, encrypt, decrypt, |_| Ok(())).is_err());
        fs::write(&path, b"corrupt").unwrap();
        assert!(Authority::load_with(&path, encrypt, decrypt, |_| Ok(())).is_err());
    }
    #[test]
    fn failed_security_setup_rolls_back_file_and_expired_roots_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.json");
        assert!(Authority::load_with(&path, |_| Ok(vec![1]), |_| Err(failure()), |_| Err(failure())).is_err());
        assert!(!path.exists());
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        let cert = params.self_signed(&key).unwrap();
        let saved = Saved { version: 1, root: cert.der().to_vec(), protected_key: vec![1] };
        fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
        assert!(Authority::load_with(&path, |_| Err(failure()), |_| Ok(key.serialize_der()), |_| Ok(())).is_err());
        assert_eq!(fs::read(&path).unwrap(), serde_json::to_vec(&saved).unwrap());
    }
    #[cfg(windows)]
    #[test]
    fn dpapi_roundtrip_and_tamper_rejection() {
        let secret = b"test-only-not-a-private-key";
        let mut cipher = protect(secret).unwrap();
        assert_ne!(cipher, secret);
        assert_eq!(unprotect(&cipher).unwrap(), secret);
        let last = cipher.len() - 1;
        cipher[last] ^= 1;
        assert!(unprotect(&cipher).is_err());
    }
}
