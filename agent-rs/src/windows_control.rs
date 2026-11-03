//! Bounded PowerShell adapter: scripts are compile-time constants; policy travels only as JSON stdin.

use crate::error::{AgentError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Event {
    pub kind: String,
    pub detail: String,
    #[serde(default = "default_rule_id")]
    pub rule_id: String,
}

fn default_rule_id() -> String {
    "policy".into()
}

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
#[cfg(windows)]
const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x0000_4000;
/// Enforcement must answer within the policy ACK window.
#[cfg(windows)]
const CONTROL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
/// Inventory hashes and verifies every running image; on busy machines it exceeded two minutes.
#[cfg(windows)]
const INVENTORY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

#[cfg(windows)]
pub fn run(script: &'static str, request: &Value) -> Result<Value> {
    run_with_limits(script, request, CREATE_NO_WINDOW, CONTROL_TIMEOUT)
}

/// Inventory collection: yields CPU so it never slows enforcement or the applications it inventories.
#[cfg(windows)]
pub fn run_background(script: &'static str, request: &Value) -> Result<Value> {
    run_with_limits(script, request, CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS, INVENTORY_TIMEOUT)
}

#[cfg(windows)]
fn run_with_limits(script: &'static str, request: &Value, flags: u32, timeout: std::time::Duration) -> Result<Value> {
    script_transport::run(script, request, flags, timeout)
}

#[cfg(windows)]
mod script_transport {
    use super::*;
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::os::windows::{
        ffi::OsStrExt,
        fs::MetadataExt,
        io::{AsRawHandle, FromRawHandle},
        process::CommandExt,
    };
    use std::path::{Component, Path, PathBuf, Prefix};
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree},
        Security::{Authorization::*, *},
        Storage::FileSystem::*,
    };

    const LIMIT: u64 = 4 * 1024 * 1024;

    fn failure(message: &str) -> AgentError {
        AgentError::Local(message.into())
    }

    fn wide(path: &Path) -> Result<Vec<u16>> {
        let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
        if value.contains(&0) {
            return Err(failure("invalid private script path"));
        }
        value.push(0);
        Ok(value)
    }

    struct LocalMemory(*mut std::ffi::c_void);
    impl Drop for LocalMemory {
        fn drop(&mut self) {
            // SAFETY: each value is allocated by a Windows API using LocalAlloc semantics.
            if !unsafe { LocalFree(self.0) }.is_null() {
                eprintln!("Windows control security buffer could not be freed");
            }
        }
    }

    fn sid_text(sid: PSID) -> Result<String> {
        let mut text = std::ptr::null_mut();
        // SAFETY: callers pass a validated SID owned by a live token/security descriptor.
        unsafe {
            if IsValidSid(sid) == 0 || ConvertSidToStringSidW(sid, &mut text) == 0 {
                return Err(failure("Windows control identity is unavailable"));
            }
            let _memory = LocalMemory(text.cast());
            let mut length = 0;
            while *text.add(length) != 0 {
                length += 1;
            }
            String::from_utf16(std::slice::from_raw_parts(text, length))
                .map_err(|_| failure("Windows control identity is invalid"))
        }
    }

    fn current_sid() -> Result<String> {
        let mut buffer = [0usize; 128];
        let mut length = 0;
        // SAFETY: the current-process token pseudo-handle needs no closing. The aligned
        // buffer is larger than TOKEN_USER plus the maximum Windows SID.
        unsafe {
            if GetTokenInformation(
                -4isize as _,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                std::mem::size_of_val(&buffer) as u32,
                &mut length,
            ) == 0
            {
                return Err(failure("Windows control identity is unavailable"));
            }
            sid_text((*(buffer.as_ptr() as *const TOKEN_USER)).User.Sid)
        }
    }

    struct PrivateSecurity {
        memory: LocalMemory,
        sid: String,
    }
    impl PrivateSecurity {
        fn new(directory: bool) -> Result<Self> {
            let sid = current_sid()?;
            let flags = if directory { "OICI" } else { "" };
            let mut sddl = format!("O:{sid}D:P(A;{flags};FA;;;{sid})");
            if sid != "S-1-5-18" {
                sddl.push_str(&format!("(A;{flags};FA;;;SY)"));
            }
            let sddl: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
            let mut descriptor = std::ptr::null_mut();
            // SAFETY: SDDL is generated only from the current token SID and fixed ACEs.
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    1,
                    &mut descriptor,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(failure("private Windows control security could not be created"));
            }
            Ok(Self { memory: LocalMemory(descriptor), sid })
        }

        fn attributes(&self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.memory.0,
                bInheritHandle: 0,
            }
        }

        fn verify(&self, file: &File, directory: bool) -> Result<()> {
            let metadata = file.metadata()?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || metadata.is_dir() != directory {
                return Err(failure("private Windows control object is not a regular file or directory"));
            }
            let mut owner = std::ptr::null_mut();
            let mut acl: *mut ACL = std::ptr::null_mut();
            let mut descriptor = std::ptr::null_mut();
            // SAFETY: GetSecurityInfo allocates the descriptor and owns all returned pointers.
            // Inspection uses a pinned handle, rather than resolving an attacker-changeable name.
            unsafe {
                if GetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    &mut owner,
                    std::ptr::null_mut(),
                    &mut acl,
                    std::ptr::null_mut(),
                    &mut descriptor,
                ) != 0
                {
                    return Err(failure("private Windows control permissions could not be verified"));
                }
                let _memory = LocalMemory(descriptor);
                let mut control = 0;
                let mut revision = 0;
                if GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) == 0
                    || control & SE_DACL_PROTECTED == 0
                    || owner.is_null()
                    || sid_text(owner)? != self.sid
                    || acl.is_null()
                {
                    return Err(failure("private Windows control owner or DACL is invalid"));
                }
                let expected = if self.sid == "S-1-5-18" { 1 } else { 2 };
                if (*acl).AceCount != expected {
                    return Err(failure("private Windows control DACL has unexpected entries"));
                }
                let mut owner_seen = false;
                let mut system_seen = false;
                for index in 0..(*acl).AceCount {
                    let mut raw = std::ptr::null_mut();
                    if GetAce(acl, index.into(), &mut raw) == 0 {
                        return Err(failure("private Windows control ACE is unavailable"));
                    }
                    let ace = &*(raw as *const ACCESS_ALLOWED_ACE);
                    // ACCESS_ALLOWED_ACE_TYPE is zero; object/callback/deny ACEs are not accepted.
                    if ace.Header.AceType != 0
                        || ace.Header.AceSize < std::mem::size_of::<ACCESS_ALLOWED_ACE>() as u16
                        || ace.Header.AceFlags
                            != if directory { (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8 } else { 0 }
                        || ace.Mask != FILE_ALL_ACCESS
                    {
                        return Err(failure("private Windows control ACE is invalid"));
                    }
                    let sid = (&ace.SidStart as *const u32).cast_mut().cast();
                    let identity = sid_text(sid)?;
                    if identity == self.sid && !owner_seen {
                        owner_seen = true;
                    } else if identity == "S-1-5-18" && !system_seen {
                        system_seen = true;
                    } else {
                        return Err(failure("private Windows control ACE trusts an unexpected identity"));
                    }
                    if identity == "S-1-5-18" {
                        system_seen = true;
                    }
                }
                if !owner_seen || !system_seen {
                    return Err(failure("private Windows control DACL omits its owner or SYSTEM"));
                }
            }
            Ok(())
        }
    }

    fn open_existing(path: &Path, directory: bool, share: u32, deletable: bool) -> Result<File> {
        let path = wide(path)?;
        let flags = FILE_FLAG_OPEN_REPARSE_POINT | if directory { FILE_FLAG_BACKUP_SEMANTICS } else { 0 };
        // SAFETY: the path is NUL-terminated; ownership of a successful handle transfers to File.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                READ_CONTROL
                    | if directory { FILE_READ_ATTRIBUTES } else { GENERIC_READ }
                    | if deletable { DELETE } else { 0 },
                share,
                std::ptr::null(),
                OPEN_EXISTING,
                flags,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    fn local_root() -> Result<(PathBuf, File)> {
        let root = std::env::temp_dir();
        let drive = match root.components().next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
                _ => return Err(failure("private Windows control temporary root must be local")),
            },
            _ => return Err(failure("private Windows control temporary root must be absolute")),
        };
        if !root.is_absolute() || root.components().any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        {
            return Err(failure("private Windows control temporary root is invalid"));
        }
        let drive_root = [drive as u16, b':' as u16, b'\\' as u16, 0];
        // SAFETY: the fixed drive-root buffer is NUL-terminated. 3/6 are local fixed/RAM drives.
        if !matches!(unsafe { GetDriveTypeW(drive_root.as_ptr()) }, 3 | 6) {
            return Err(failure("private Windows control temporary root must be on a local disk"));
        }
        check_existing_ancestors(&root)?;
        let pinned = open_existing(&root, true, FILE_SHARE_READ | FILE_SHARE_WRITE, false)?;
        if !pinned.metadata()?.is_dir() || pinned.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(failure("private Windows control temporary root is not a directory"));
        }
        check_existing_ancestors(&root)?;
        Ok((root, pinned))
    }

    fn check_existing_ancestors(path: &Path) -> Result<()> {
        for ancestor in path.ancestors() {
            // Every ancestor of an existing temporary root must be readable; an inspection error is not trust.
            let metadata = fs::symlink_metadata(ancestor)?;
            if metadata.file_type().is_symlink() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(failure("private Windows control root contains a reparse point"));
            }
        }
        Ok(())
    }

    struct StagedScript {
        directory: PathBuf,
        path: PathBuf,
        root_guard: Option<File>,
        directory_guard: Option<File>,
        file_guard: Option<File>,
        file_created: bool,
        cleanup_attempted: bool,
        retain: bool,
    }

    impl StagedScript {
        fn new(script: &str) -> Result<Self> {
            if script.len() as u64 > LIMIT {
                return Err(failure("trusted Windows control script exceeds its size limit"));
            }
            let (root, root_guard) = local_root()?;
            let security = PrivateSecurity::new(true)?;
            let attributes = security.attributes();
            let mut selected = None;
            for _ in 0..16 {
                let path = root.join(format!(".openems-control-{:016x}{:016x}", fastrand::u64(..), fastrand::u64(..)));
                let wide = wide(&path)?;
                // SAFETY: a protected DACL and owner are supplied at atomic directory creation.
                if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } != 0 {
                    selected = Some(path);
                    break;
                }
                let error = std::io::Error::last_os_error();
                if !matches!(error.raw_os_error(), Some(80 | 183)) {
                    return Err(error.into());
                }
            }
            let directory =
                selected.ok_or_else(|| failure("private Windows control directory collision limit reached"))?;
            let mut staged = Self {
                path: directory.join("control.ps1"),
                directory,
                root_guard: Some(root_guard),
                directory_guard: None,
                file_guard: None,
                file_created: false,
                cleanup_attempted: false,
                retain: false,
            };
            let populated = staged.populate(script, &security);
            if let Err(error) = populated {
                return combine(Err(error), staged.cleanup());
            }
            Ok(staged)
        }

        fn populate(&mut self, script: &str, directory_security: &PrivateSecurity) -> Result<()> {
            let directory_guard = open_existing(&self.directory, true, FILE_SHARE_READ | FILE_SHARE_WRITE, true)?;
            directory_security.verify(&directory_guard, true)?;
            self.directory_guard = Some(directory_guard);
            crate::authority::check_path(&self.path)?;
            let security = PrivateSecurity::new(false)?;
            let attributes = security.attributes();
            let path = wide(&self.path)?;
            // SAFETY: CREATE_NEW refuses existing files/reparse points and starts with the private DACL.
            let handle = unsafe {
                CreateFileW(
                    path.as_ptr(),
                    GENERIC_WRITE | READ_CONTROL,
                    FILE_SHARE_READ,
                    &attributes,
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                    std::ptr::null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(std::io::Error::last_os_error().into());
            }
            self.file_created = true;
            let mut writer = unsafe { File::from_raw_handle(handle) };
            security.verify(&writer, false)?;
            writer.write_all(b"\xef\xbb\xbf")?;
            writer.write_all(script.strip_prefix('\u{feff}').unwrap_or(script).as_bytes())?;
            writer.sync_all()?;
            drop(writer);
            self.file_guard = Some(open_existing(&self.path, false, FILE_SHARE_READ, false)?);
            security.verify(self.file_guard.as_ref().unwrap(), false)?;
            crate::authority::check_path(&self.path)?;
            Ok(())
        }

        fn cleanup(&mut self) -> Result<()> {
            if self.retain {
                return Err(failure("Windows control process could not be stopped; private script retained"));
            }
            self.cleanup_attempted = true;
            if self.directory_guard.is_none() {
                drop(self.root_guard.take());
                return Err(failure("Windows control directory identity was not verified; directory retained"));
            }
            drop(self.file_guard.take());
            let file = if self.file_created { fs::remove_file(&self.path) } else { Ok(()) };
            let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
            // SAFETY: the verified owned directory remains pinned. Mark this object for deletion
            // before closing its handle so another Temp user cannot swap a pathname into cleanup.
            let directory = if unsafe {
                SetFileInformationByHandle(
                    self.directory_guard.as_ref().unwrap().as_raw_handle(),
                    FileDispositionInfo,
                    (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                    std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
                )
            } == 0
            {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            };
            drop(self.directory_guard.take());
            drop(self.root_guard.take());
            file.and(directory).map_err(|_| failure("Windows control private script cleanup failed"))
        }
    }

    impl Drop for StagedScript {
        fn drop(&mut self) {
            if self.retain {
                // If Windows cannot stop our child, keep its integrity pins until the agent exits.
                std::mem::forget(self.file_guard.take());
                std::mem::forget(self.directory_guard.take());
                std::mem::forget(self.root_guard.take());
                eprintln!("Windows control private script retained because its process state is unknown");
            } else if !self.cleanup_attempted && self.cleanup().is_err() {
                eprintln!("Windows control private script cleanup failed");
            }
        }
    }

    fn combine<T>(outcome: Result<T>, cleanup: Result<()>) -> Result<T> {
        match (outcome, cleanup) {
            (result, Ok(())) => result,
            (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(_)) => Err(failure(&format!("{error}; private script cleanup failed"))),
        }
    }

    struct Streams {
        input: Result<()>,
        output: Result<Vec<u8>>,
        diagnostics: Result<Vec<u8>>,
    }
    impl Streams {
        fn failed(&self) -> bool {
            self.input.is_err() || self.output.is_err() || self.diagnostics.is_err()
        }
    }

    struct ControlProcess<'a> {
        staged: &'a mut StagedScript,
        child: Child,
        input: Option<JoinHandle<std::io::Result<()>>>,
        output: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
        diagnostics: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
        stopped: bool,
    }

    impl<'a> ControlProcess<'a> {
        fn spawn(staged: &'a mut StagedScript, bytes: Vec<u8>, flags: u32) -> Result<Self> {
            let root = std::env::var_os("SystemRoot").ok_or_else(|| failure("Windows directory unavailable"))?;
            let executable = Path::new(&root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
            // PowerShell 7's inherited module path can select incompatible assemblies in Windows PowerShell 5.1.
            let modules = Path::new(&root).join("System32/WindowsPowerShell/v1.0/Modules");
            let child = Command::new(executable)
                .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"])
                .arg(&staged.path)
                .env("PSModulePath", modules)
                .creation_flags(flags)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            let mut process = Self { staged, child, input: None, output: None, diagnostics: None, stopped: false };
            let stdout = process.child.stdout.take().ok_or_else(|| failure("control output unavailable"))?;
            process.output = Some(std::thread::Builder::new().name("control-output".into()).spawn(move || {
                let mut bytes = Vec::new();
                stdout.take(LIMIT + 1).read_to_end(&mut bytes).map(|_| bytes)
            })?);
            let stderr = process.child.stderr.take().ok_or_else(|| failure("control diagnostics unavailable"))?;
            process.diagnostics =
                Some(std::thread::Builder::new().name("control-diagnostics".into()).spawn(move || {
                    let mut bytes = Vec::new();
                    stderr.take(64 * 1024).read_to_end(&mut bytes).map(|_| bytes)
                })?);
            let mut stdin = process.child.stdin.take().ok_or_else(|| failure("control input unavailable"))?;
            process.input =
                Some(std::thread::Builder::new().name("control-input".into()).spawn(move || stdin.write_all(&bytes))?);
            Ok(process)
        }

        fn wait(&mut self, timeout: Duration) -> Result<ExitStatus> {
            let deadline = Instant::now() + timeout;
            loop {
                if let Some(status) = self.child.try_wait()? {
                    self.stopped = true;
                    return Ok(status);
                }
                if Instant::now() >= deadline {
                    return Err(failure("Windows control timed out; its journal is retained for recovery"));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }

        fn stop(&mut self) -> Result<()> {
            if self.stopped {
                return Ok(());
            }
            if self.child.try_wait()?.is_none()
                && let Err(error) = self.child.kill()
                && self.child.try_wait()?.is_none()
            {
                return Err(error.into());
            }
            self.child.wait()?;
            self.stopped = true;
            Ok(())
        }

        fn collect(&mut self) -> Streams {
            fn join<T>(thread: Option<JoinHandle<std::io::Result<T>>>, missing: T) -> Result<T> {
                match thread {
                    Some(thread) => {
                        thread.join().map_err(|_| failure("control I/O worker failed"))?.map_err(Into::into)
                    }
                    None => Ok(missing),
                }
            }
            // Join every worker before checking any result, including on process failure.
            let input = join(self.input.take(), ());
            let output = join(self.output.take(), Vec::new());
            let diagnostics = join(self.diagnostics.take(), Vec::new());
            Streams { input, output, diagnostics }
        }

        fn execute(&mut self, timeout: Duration) -> Result<Value> {
            let status = match self.wait(timeout) {
                Ok(status) => status,
                Err(error) => {
                    self.stop()?;
                    let streams = self.collect();
                    return if streams.failed() {
                        Err(failure(&format!("{error}; control I/O ended while stopping")))
                    } else {
                        Err(error)
                    };
                }
            };
            let streams = self.collect();
            let bytes = streams.output?;
            let diagnostics = streams.diagnostics;
            if !status.success() || streams.input.is_err() || diagnostics.is_err() || bytes.len() as u64 > LIMIT {
                let error = serde_json::from_slice::<Value>(&bytes).ok();
                let message = match error.as_ref().and_then(|value| value["error"].as_str()) {
                    Some("restart_required") => "Windows control requires a restart; its protected journal is retained",
                    Some("unsupported") => "Windows does not support the requested control",
                    _ => "Windows control failed; verify OS support and its protected journal",
                };
                return Err(failure(message));
            }
            serde_json::from_slice(&bytes).map_err(|_| failure("Windows control returned invalid output"))
        }
    }

    impl Drop for ControlProcess<'_> {
        fn drop(&mut self) {
            if self.stop().is_err() {
                self.staged.retain = true;
                eprintln!("Windows control process could not be stopped; private script retained");
            } else if self.collect().failed() {
                eprintln!("Windows control I/O did not complete during process cleanup");
            }
        }
    }

    pub(super) fn run(script: &'static str, request: &Value, flags: u32, timeout: Duration) -> Result<Value> {
        let bytes = serde_json::to_vec(request).map_err(|_| failure("invalid control request"))?;
        if bytes.len() as u64 > LIMIT {
            return Err(failure("control request exceeds its size limit"));
        }
        let mut staged = StagedScript::new(script)?;
        let outcome = ControlProcess::spawn(&mut staged, bytes, flags).and_then(|mut process| process.execute(timeout));
        combine(outcome, staged.cleanup())
    }

    #[cfg(test)]
    mod security_tests {
        use super::*;
        use serde_json::json;

        #[test]
        fn cleanup_preserves_a_directory_that_was_never_verified() {
            let root = tempfile::tempdir().unwrap();
            let directory = root.path().join("unverified");
            fs::create_dir(&directory).unwrap();
            let mut staged = StagedScript {
                path: directory.join("control.ps1"),
                directory: directory.clone(),
                root_guard: None,
                directory_guard: None,
                file_guard: None,
                file_created: false,
                cleanup_attempted: false,
                retain: false,
            };
            let result = staged.cleanup();
            let preserved = directory.is_dir();
            drop(staged);
            if preserved {
                fs::remove_dir(&directory).unwrap();
            }
            assert!(result.is_err(), "cleanup must report that it cannot establish directory ownership");
            assert!(preserved, "an unverified path must never be removed");
        }

        #[test]
        fn staging_rejects_exhausted_collisions_without_removing_existing_directories() {
            let (root, pin) = local_root().unwrap();
            let seed = fastrand::u64(..);
            let mut rng = fastrand::Rng::with_seed(seed);
            let paths: Vec<_> = (0..16)
                .map(|_| root.join(format!(".openems-control-{:016x}{:016x}", rng.u64(..), rng.u64(..))))
                .collect();
            for path in &paths {
                fs::create_dir(path).unwrap();
            }
            fastrand::seed(seed);
            let result = StagedScript::new("'{}'");
            let all_preserved = paths.iter().all(|path| path.is_dir());
            for path in &paths {
                fs::remove_dir(path).unwrap();
            }
            drop(pin);
            assert!(result.is_err_and(|error| error.to_string().contains("collision limit")));
            assert!(all_preserved, "collision paths belong to other invocations");
        }

        #[test]
        fn staged_script_rejects_an_extra_trusted_identity() {
            let mut staged = StagedScript::new("'{}'").unwrap();
            crate::fsutil::secure_file_with(&staged.path, "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FR;;;WD)").unwrap();
            let rejected = PrivateSecurity::new(false).unwrap().verify(staged.file_guard.as_ref().unwrap(), false);
            staged.cleanup().unwrap();
            assert!(rejected.is_err(), "Everyone must not gain access to the staged file");
        }

        #[test]
        fn staging_rejects_oversized_compiled_source() {
            let script = "x".repeat(LIMIT as usize + 1);
            assert!(StagedScript::new(&script).is_err_and(|error| error.to_string().contains("size limit")));
        }

        #[test]
        fn cleanup_reports_unexpected_content_without_removing_it() {
            let mut staged = StagedScript::new("'{}'").unwrap();
            let extra = staged.directory.join("unexpected.txt");
            fs::write(&extra, b"owned test marker; preserve this file").unwrap();
            let result = staged.cleanup();
            let preserved = fs::read(&extra).unwrap();
            let directory = staged.directory.clone();
            drop(staged);
            fs::remove_file(extra).unwrap();
            fs::remove_dir(directory).unwrap();
            assert!(result.is_err(), "a nonempty staging directory must prevent successful cleanup");
            assert_eq!(preserved, b"owned test marker; preserve this file");
        }

        #[test]
        fn private_object_checks_refuse_a_directory_junction() {
            let root = tempfile::tempdir().unwrap();
            let target = root.path().join("target");
            let junction = root.path().join("junction");
            fs::create_dir(&target).unwrap();
            const CREATE_JUNCTION: &str = "$ErrorActionPreference='Stop'; $r=[Console]::In.ReadToEnd()|ConvertFrom-Json; New-Item -ItemType Junction -Path $r.path -Target $r.target|Out-Null; '{}'";
            let response = super::run(
                CREATE_JUNCTION,
                &json!({"path":junction,"target":target}),
                CREATE_NO_WINDOW,
                Duration::from_secs(10),
            );
            let checked = response.and_then(|_| {
                let file = open_existing(&junction, true, FILE_SHARE_READ | FILE_SHARE_WRITE, false)?;
                PrivateSecurity::new(true)?.verify(&file, true)
            });
            let path_rejected = crate::authority::check_path(&junction).is_err();
            if junction.exists() {
                fs::remove_dir(&junction).unwrap();
            }
            fs::remove_dir(&target).unwrap();
            assert!(checked.is_err());
            assert!(path_rejected, "a junction ancestor must be rejected");
        }
    }
}

#[cfg(not(windows))]
pub fn run(_script: &'static str, _request: &Value) -> Result<Value> {
    Err(AgentError::Local("this control adapter requires Windows".into()))
}

#[cfg(not(windows))]
pub fn run_background(script: &'static str, request: &Value) -> Result<Value> {
    run(script, request)
}

pub fn path(path: &std::path::Path) -> Result<&str> {
    path.to_str().ok_or_else(|| AgentError::Local("control state path is not valid Unicode".into()))
}

pub fn invalid(message: &str) -> AgentError {
    AgentError::Policy(message.into())
}

pub fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

pub fn text(value: &str, limit: usize) -> bool {
    !value.is_empty() && value == value.trim() && value.chars().count() <= limit && !value.chars().any(char::is_control)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use serde_json::json;

    const USB: &str = include_str!("../../deploy/agent-usb.ps1");
    const APPLICATIONS: &str = include_str!("../../deploy/agent-applications.ps1");

    fn inert_transport_script(body: &str) -> &'static str {
        let script = format!(
            "$ErrorActionPreference='Stop'; [Console]::InputEncoding=New-Object Text.UTF8Encoding($false); [Console]::OutputEncoding=New-Object Text.UTF8Encoding($false); $request=[Console]::In.ReadToEnd()|ConvertFrom-Json;\n{body}"
        );
        Box::leak(script.into_boxed_str())
    }

    fn assert_transport_artifacts_removed(path: &str) {
        assert!(!path.is_empty(), "the trusted script must have a private file path");
        let file = std::path::Path::new(path);
        assert!(!file.exists(), "the temporary script must be removed after the child stops");
        assert!(!file.parent().unwrap().exists(), "the per-call private directory must be removed");
    }

    #[test]
    fn native_transport_runs_a_trusted_script_beyond_the_windows_command_line_limit() {
        let script = inert_transport_script(&format!(
            "#{}\n$request|ConvertTo-Json -Depth 8 -Compress",
            "inert-comment-".repeat(3200)
        ));
        assert!(script.encode_utf16().count() > 32767);
        let request = json!({"marker":"synthetic-large-script", "quoted":"a\"b\nc"});

        let response = run_with_limits(script, &request, CREATE_NO_WINDOW, std::time::Duration::from_secs(10));

        assert_eq!(response.unwrap(), request);
    }

    #[test]
    fn native_transport_keeps_json_off_disk_and_stages_unicode_with_private_permissions() {
        let script = inert_transport_script(
            r#"$result=@{staged=$false;literal='ação — 日本語';request=$request}
if($PSCommandPath) {
    $path=[IO.Path]::GetFullPath($PSCommandPath)
    $directory=[IO.Path]::GetDirectoryName($path)
    $bytes=[IO.File]::ReadAllBytes($path)
    $fileAcl=Get-Acl -LiteralPath $path
    $directoryAcl=Get-Acl -LiteralPath $directory
    $result.staged=$true
    $result.path=$path
    $result.current_sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $result.file_owner=$fileAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $result.directory_owner=$directoryAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $result.directory_protected=$directoryAcl.AreAccessRulesProtected
    $result.file_rules=@($fileAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {@{sid=$_.IdentityReference.Value;access=[string]$_.AccessControlType}})
    $result.directory_rules=@($directoryAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {@{sid=$_.IdentityReference.Value;access=[string]$_.AccessControlType}})
    $result.utf8_bom=($bytes.Length-ge3-and$bytes[0]-eq239-and$bytes[1]-eq187-and$bytes[2]-eq191)
    $result.request_marker_on_disk=[Text.Encoding]::UTF8.GetString($bytes).Contains([string]$request.marker)
}
$result|ConvertTo-Json -Depth 8 -Compress"#,
        );
        let marker = format!("stdin-only-{:016x}", fastrand::u64(..));
        let request = json!({"marker":marker, "nested":{"quoted":"a\"b\nc", "unicode":"日本語"}});

        let response = run(script, &request).unwrap();

        assert_eq!(response["staged"], true, "{response}");
        assert_eq!(response["literal"], "ação — 日本語");
        assert_eq!(response["request"], request);
        assert_eq!(response["utf8_bom"], true);
        assert_eq!(response["request_marker_on_disk"], false);
        assert_eq!(response["directory_protected"], true);
        assert_eq!(response["file_owner"], response["current_sid"]);
        assert_eq!(response["directory_owner"], response["current_sid"]);
        let current_sid = response["current_sid"].as_str().unwrap();
        for name in ["file_rules", "directory_rules"] {
            let rules = response[name].as_array().unwrap();
            assert!(!rules.is_empty());
            for rule in rules {
                assert_eq!(rule["access"], "Allow");
                assert!(matches!(rule["sid"].as_str(), Some(sid) if sid == current_sid || sid == "S-1-5-18"));
            }
            assert!(rules.iter().any(|rule| rule["sid"] == current_sid));
            assert!(rules.iter().any(|rule| rule["sid"] == "S-1-5-18"));
        }
        assert_transport_artifacts_removed(response["path"].as_str().unwrap());
    }

    #[test]
    fn native_transport_prevents_script_writes_and_replacement_while_it_runs() {
        let script = inert_transport_script(
            r#"$result=@{staged=$false;write_blocked=$false;rename_blocked=$false}
if($PSCommandPath) {
    $path=[IO.Path]::GetFullPath($PSCommandPath)
    $directory=[IO.Path]::GetDirectoryName($path)
    $temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
    $acl=Get-Acl -LiteralPath $directory
    $current=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if(-not $path.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or
       $directory.TrimEnd('\') -ieq $temp.TrimEnd('\') -or
       [IO.Path]::GetFileName($path) -cne 'control.ps1' -or
       -not $acl.AreAccessRulesProtected -or
       $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $current) {
        throw 'Write probes require an owned private per-call script under the local temporary root.'
    }
    $result.staged=$true; $result.path=$path
    try { $writer=[IO.File]::Open($PSCommandPath,'Open','Write','ReadWrite'); $writer.Dispose() }
    catch [IO.IOException] { $result.write_blocked=$true }
    $renamed=$PSCommandPath+'.renamed'
    try { [IO.File]::Move($PSCommandPath,$renamed); [IO.File]::Move($renamed,$PSCommandPath) }
    catch [IO.IOException] { $result.rename_blocked=$true }
}
$result|ConvertTo-Json -Compress"#,
        );

        let response = run(script, &json!({})).unwrap();

        assert_eq!(response["staged"], true);
        assert_eq!(response["write_blocked"], true, "the parent must pin the script against concurrent writes");
        assert_eq!(response["rename_blocked"], true, "the parent must pin the script against replacement");
        assert_transport_artifacts_removed(response["path"].as_str().unwrap());
    }

    #[test]
    fn native_transport_uses_unique_private_paths_for_parallel_calls() {
        let script =
            inert_transport_script("Start-Sleep -Milliseconds 200; @{path=$PSCommandPath}|ConvertTo-Json -Compress");

        let workers: Vec<_> = (0..3).map(|_| std::thread::spawn(move || run(script, &json!({})).unwrap())).collect();
        let responses: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
        let paths: std::collections::BTreeSet<_> = responses.iter().map(|row| row["path"].as_str().unwrap()).collect();

        assert_eq!(paths.len(), 3, "parallel calls must not reuse a staged script");
        let parents: std::collections::BTreeSet<_> =
            paths.iter().map(|path| std::path::Path::new(path).parent().unwrap()).collect();
        assert_eq!(parents.len(), 3, "each invocation must own its private directory");
        for path in paths {
            assert_transport_artifacts_removed(path);
        }
    }

    fn assert_inert_transport_failure_cleanup(ending: &str, timeout: std::time::Duration, expect_timeout: bool) {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("owned-script-path.txt");
        let script = inert_transport_script(&format!(
            "[IO.File]::WriteAllText([string]$request.marker_path,[string]$PSCommandPath); {ending}"
        ));

        let failure = run_with_limits(script, &json!({"marker_path":marker}), CREATE_NO_WINDOW, timeout).unwrap_err();

        if expect_timeout {
            assert!(failure.to_string().contains("timed out"), "{failure}");
        }
        let staged = std::fs::read_to_string(marker).expect("the inert child must publish its path before failing");
        assert_transport_artifacts_removed(&staged);
    }

    #[test]
    fn native_transport_cleans_private_artifacts_after_child_failure() {
        assert_inert_transport_failure_cleanup("exit 17", std::time::Duration::from_secs(10), false);
    }

    #[test]
    fn native_transport_cleans_private_artifacts_after_invalid_json_output() {
        assert_inert_transport_failure_cleanup("'not-json'", std::time::Duration::from_secs(10), false);
    }

    #[test]
    fn native_transport_stops_the_child_before_cleaning_artifacts_after_timeout() {
        assert_inert_transport_failure_cleanup(
            "Start-Sleep -Seconds 15; '{}'",
            std::time::Duration::from_secs(5),
            true,
        );
    }

    #[test]
    fn native_transport_rejects_oversized_json_before_starting_the_script() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("must-not-exist.txt");
        let script =
            inert_transport_script("[IO.File]::WriteAllText([string]$request.marker_path,'unexpected'); '{}' ");
        let request = json!({"marker_path":marker,"payload":"x".repeat(4 * 1024 * 1024)});

        let failure = run(script, &request).unwrap_err();

        assert!(failure.to_string().contains("size limit"), "{failure}");
        assert!(!marker.exists());
    }

    #[test]
    fn background_inventory_gets_a_longer_limit_than_enforcement() {
        // A real notebook's application inventory exceeded the 120 s enforcement limit.
        assert_eq!(CONTROL_TIMEOUT, std::time::Duration::from_secs(120));
        assert!(INVENTORY_TIMEOUT >= std::time::Duration::from_secs(600));
        const SLOW: &str = "[Console]::In.ReadToEnd()|Out-Null; Start-Sleep -Seconds 5; '{}'";
        let error =
            run_with_limits(SLOW, &json!({}), CREATE_NO_WINDOW, std::time::Duration::from_millis(500)).unwrap_err();
        assert!(error.to_string().contains("timed out"));
    }

    #[test]
    fn background_collection_yields_cpu_to_enforcement() {
        const PRIORITY: &str = "$request=[Console]::In.ReadToEnd()|ConvertFrom-Json; @{priority=[string](Get-Process -Id $PID).PriorityClass; parent=[string](Get-Process -Id $request.parent).PriorityClass}|ConvertTo-Json -Compress";
        let request = json!({ "parent": std::process::id() });
        let foreground = run(PRIORITY, &request).unwrap();
        // Without a priority flag Windows starts children at Normal, unless the parent runs at Idle or
        // BelowNormal (as CI runners do), in which case the child inherits the parent's class.
        let parent = foreground["parent"].as_str().unwrap().to_owned();
        let expected = if matches!(parent.as_str(), "Idle" | "BelowNormal") { parent.as_str() } else { "Normal" };
        assert_eq!(foreground["priority"], expected);
        assert_eq!(run_background(PRIORITY, &request).unwrap()["priority"], "BelowNormal");
    }

    #[test]
    fn inventories_run_as_background_collections() {
        for source in [include_str!("usb.rs"), include_str!("applications.rs")] {
            assert!(source.contains(r#"adapter::run_background(SCRIPT, &json!({"mode":"inventory"}))"#));
            assert!(!source.contains(r#"adapter::run(SCRIPT, &json!({"mode":"inventory"}))"#));
        }
    }

    #[test]
    fn embedded_scripts_parse_without_running_any_mutation() {
        const PARSER: &str = "$ErrorActionPreference='Stop'; $r=[Console]::In.ReadToEnd()|ConvertFrom-Json; $e=$null; [System.Management.Automation.PSParser]::Tokenize($r.source,[ref]$e)|Out-Null; @{errors=@($e|ForEach-Object Message)}|ConvertTo-Json -Compress";
        for script in [USB, APPLICATIONS] {
            assert_eq!(run(PARSER, &json!({"source":script})).unwrap()["errors"], json!([]));
        }
    }

    #[test]
    fn usb_inventory_reads_product_id_without_overwriting_powershell_pid() {
        let script = format!(
            "function Get-PnpDevice {{ [pscustomobject]@{{InstanceId='USB\\VID_0781&PID_5581\\sample';Class='HIDClass';FriendlyName='Fixture'}} }}\nfunction Get-CimInstance {{ @() }}\nfunction Get-PnpDeviceProperty {{ [pscustomobject]@{{Data='Fixture'}} }}\n{USB}"
        );
        let script: &'static str = Box::leak(script.into_boxed_str());
        let result = run(script, &json!({"mode":"inventory"})).unwrap();
        assert_eq!(result["inventory"][0]["pid"], "5581");
        assert_eq!(result["inventory"][0]["class"], "hid");
    }

    #[test]
    fn usb_inventory_skips_virtual_non_usb_disks_before_querying_storage_management() {
        let script = format!(
            r#"function Get-PnpDevice {{ [pscustomobject]@{{InstanceId='SCSI\DISK&VEN_MSFT\VIRTUAL';Class='DiskDrive';FriendlyName='Virtual disk'}} }}
function Get-CimInstance {{ [pscustomobject]@{{PNPDeviceID='SCSI\DISK&VEN_MSFT\VIRTUAL';Index=0;InterfaceType='SCSI'}} }}
function Get-PnpDeviceProperty {{ [pscustomobject]@{{Data=$null}} }}
function Get-Disk {{ throw 'Storage management is unavailable for the non-USB virtual disk' }}
{USB}"#
        );
        let script: &'static str = Box::leak(script.into_boxed_str());
        let result = run(script, &json!({"mode":"inventory"})).unwrap();
        assert_eq!(result["inventory"], json!([]));
    }

    #[test]
    fn usb_inventory_keeps_storage_identity_and_boot_protection_for_all_usb_evidence() {
        for (instance, ancestor, interface) in [
            (r"USBSTOR\DISK\sample", "", "SCSI"),
            (r"SCSI\DISK\sample", r"USB\VID_0781&PID_5581\sample", "SCSI"),
            (r"SCSI\DISK\sample", "", "USB"),
        ] {
            let script = format!(
                r#"function Get-PnpDevice {{ [pscustomobject]@{{InstanceId='{instance}';Class='DiskDrive';FriendlyName='USB storage'}} }}
function Get-CimInstance {{ [pscustomobject]@{{PNPDeviceID='{instance}';Index=2;InterfaceType='{interface}';SerialNumber='SERIAL';Manufacturer='Fixture';Model='Storage'}} }}
function Get-PnpDeviceProperty {{ param($InstanceId,$KeyName) [pscustomobject]@{{Data=$(if ($KeyName -eq 'DEVPKEY_Device_Parent' -and $InstanceId -eq '{instance}') {{ '{ancestor}' }} else {{ '' }})}} }}
function Get-Disk {{ [pscustomobject]@{{BusType='USB';Number=2;UniqueId='unique-fixture';IsBoot=$true;IsSystem=$true}} }}
function Get-Partition {{ @() }}
{USB}"#
            );
            let script: &'static str = Box::leak(script.into_boxed_str());
            let result = run(script, &json!({"mode":"inventory"})).unwrap();
            assert_eq!(result["inventory"][0]["class"], "storage");
            assert_eq!(result["inventory"][0]["disk_unique_id"], "unique-fixture");
            assert_eq!(result["inventory"][0]["is_boot"], true);
            assert_eq!(result["inventory"][0]["is_system"], true);
        }
    }

    #[test]
    fn usb_inventory_does_not_hide_real_usb_storage_query_failures() {
        let script = format!(
            r#"function Get-PnpDevice {{ [pscustomobject]@{{InstanceId='USBSTOR\DISK\sample';Class='DiskDrive';FriendlyName='USB storage'}} }}
function Get-CimInstance {{ [pscustomobject]@{{PNPDeviceID='USBSTOR\DISK\sample';Index=2;InterfaceType='USB'}} }}
function Get-PnpDeviceProperty {{ [pscustomobject]@{{Data=$null}} }}
function Get-Disk {{ throw 'Real USB storage identity cannot be verified' }}
{USB}"#
        );
        let script: &'static str = Box::leak(script.into_boxed_str());
        assert!(run(script, &json!({"mode":"inventory"})).is_err());
    }

    #[test]
    fn application_inventory_tolerates_empty_uninstall_registry_keys() {
        let script = format!(
            "function Get-CimInstance {{ @() }}\nfunction Test-Path {{ $true }}\nfunction Get-ChildItem {{ [pscustomobject]@{{PSPath='fixture';PSChildName='empty'}} }}\nfunction Get-ItemProperty {{ $null }}\n{APPLICATIONS}"
        );
        let script: &'static str = Box::leak(script.into_boxed_str());
        let result = run(script, &json!({"mode":"inventory"})).unwrap();
        assert_eq!(result["inventory"], json!([]));
    }

    #[test]
    fn usb_script_plan_preserves_hid_and_boot_storage() {
        let result = run(
            USB,
            &json!({"mode":"plan", "policy":{"default_action":"block","rules":[
                {"id":"approved","action":"allow","vid":"0781","serial":"SERIAL"}
            ]}, "inventory":[
                {"instance_id":"HID\\mouse","class":"mouse"},
                {"instance_id":"USBSTOR\\boot","class":"storage","is_boot":true},
                {"instance_id":"USBSTOR\\allowed","class":"storage","vid":"0781","serial":"SERIAL"},
                {"instance_id":"USBSTOR\\blocked","class":"storage","vid":"0781","serial":"OTHER"}
            ]}),
        )
        .unwrap();
        assert_eq!(result["changes"], json!([{"instance_id":"USBSTOR\\blocked","action":"block"}]));
    }

    #[test]
    fn code_integrity_events_need_enforcement_id_and_the_owned_policy_guid() {
        let guid = "{83D4D642-7C56-470C-AFA1-E6988DA8FE7C}";
        for (event_id, policy, expected) in
            [(3077, guid, true), (3076, guid, false), (3077, "{00000000-0000-0000-0000-000000000000}", false)]
        {
            let xml = format!(
                "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>{event_id}</EventID></System><EventData><Data Name=\"PolicyGUID\">{policy}</Data><Data Name=\"FileName\">C:\\Tools\\denied.exe</Data></EventData></Event>"
            );
            let result = run(APPLICATIONS, &json!({"mode":"event-plan","policy_id":guid,"xml":xml})).unwrap();
            assert_eq!(result["events"].as_array().unwrap().len(), usize::from(expected));
            if expected {
                assert_eq!(result["events"][0]["kind"], "app_block");
                assert_eq!(result["events"][0]["rule_id"], guid.trim_matches(['{', '}']));
            }
        }
        assert!(run(APPLICATIONS, &json!({"mode":"event-plan","policy_id":guid,"xml":"<!DOCTYPE x [<!ENTITY y SYSTEM 'file:///C:/private'>]><Event>&y;</Event>"})).is_err());
    }

    #[test]
    fn non_system_apply_refuses_before_creating_a_journal() {
        if crate::authority::require_system().is_ok() {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let journal = directory.path().join("must-not-exist.json");
        for script in [USB, APPLICATIONS] {
            assert!(run(script, &json!({"mode":"apply","state_path":journal,"policy":{}})).is_err());
            assert!(!journal.exists());
        }
    }
}
