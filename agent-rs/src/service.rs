//! Windows service host and registration with automatic start and recovery.

use crate::app;
use crate::config::{AgentConfig, data_dir, default_config_path};
use crate::error::{AgentError, Result};
use crate::hardening::{SERVICE_SDDL, ServiceSnapshot, WatchdogAction, same_dacl, watchdog_actions, watchdog_task_xml};
use crate::hosts::clear_hosts;
use crate::logging::file_logger;
use crate::runtime::StopSignal;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl,
    ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "openems-agent";
/// SYSTEM task that starts the service again if it was disabled or stopped (tamper-protection.md, decision 3).
pub const WATCHDOG_TASK: &str = "openems-agent watchdog";
const DISPLAY_NAME: &str = "openems endpoint agent";
const DESCRIPTION: &str = "Applies RSM endpoint policies and reports their status to the management server.";

static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

fn service_error(error: windows_service::Error) -> AgentError {
    AgentError::Local(format!("service control failed: {error}"))
}

/// Hand the process to the Service Control Manager; returns when the service stops.
pub fn run_dispatcher(config: Option<PathBuf>) -> Result<()> {
    let _ = CONFIG_PATH.set(config.unwrap_or_else(default_config_path));
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(service_error)
}

fn status(state: ServiceState, exit_code: ServiceExitCode) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}

/// Reported as soon as a stop is requested: cleanup (NRPT removal, listener joins) can take a few
/// seconds, and Stop-Service treats a stopping service that still reports Running as failed.
fn stop_pending_status() -> ServiceStatus {
    ServiceStatus {
        checkpoint: 1,
        wait_hint: Duration::from_secs(30),
        ..status(ServiceState::StopPending, ServiceExitCode::Win32(0))
    }
}

fn service_main(_arguments: Vec<OsString>) {
    let stop = Arc::new(StopSignal::default());
    let handler_stop = Arc::clone(&stop);
    let Ok(handle) = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            handler_stop.stop();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }) else {
        return;
    };
    let _ = handle.set_service_status(status(ServiceState::Running, ServiceExitCode::Win32(0)));
    // The lock orders the pending report before the final Stopped report, never after it.
    let finished = Arc::new(Mutex::new(false));
    let watcher = {
        let (stop, finished) = (Arc::clone(&stop), Arc::clone(&finished));
        std::thread::spawn(move || {
            while !stop.wait(Duration::from_secs(3600)) {}
            if !*finished.lock().unwrap_or_else(|poison| poison.into_inner()) {
                let _ = handle.set_service_status(stop_pending_status());
            }
        })
    };
    let config_path = CONFIG_PATH.get().cloned().unwrap_or_else(default_config_path);
    let outcome = file_logger(&data_dir().join("agent.log")).and_then(|log| {
        let config = AgentConfig::from_file(&config_path);
        if let Err(error) = &config {
            log(&format!("configuration rejected: {error}"));
        }
        let result = config.and_then(|config| app::run_as_service(config, Arc::clone(&log), Arc::clone(&stop)));
        if let Err(error) = &result {
            log(&format!("agent stopped with an error ({})", error.kind()));
        }
        result
    });
    // A non-zero exit lets the configured failure actions restart the agent.
    let exit = if outcome.is_ok() { ServiceExitCode::Win32(0) } else { ServiceExitCode::ServiceSpecific(1) };
    {
        let mut done = finished.lock().unwrap_or_else(|poison| poison.into_inner());
        *done = true;
        let _ = handle.set_service_status(status(ServiceState::Stopped, exit));
    }
    // Wakes the watcher when the agent ended on its own (an error), so the thread exits.
    stop.stop();
    let _ = watcher.join();
}

/// Register the running executable as an auto-start LocalSystem service that restarts on failure.
pub fn install(config: Option<PathBuf>, start: bool) -> Result<()> {
    let config_path = config.unwrap_or_else(default_config_path);
    AgentConfig::from_file(&config_path)?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(service_error)?;
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments: vec!["service".into(), "--config".into(), config_path.into_os_string()],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let service = manager
        .create_service(
            &info,
            ServiceAccess::CHANGE_CONFIG
                | ServiceAccess::START
                | ServiceAccess::QUERY_STATUS
                | ServiceAccess::READ_CONTROL
                | ServiceAccess::WRITE_DAC,
        )
        .map_err(service_error)?;
    service.set_description(DESCRIPTION).map_err(service_error)?;
    apply_recovery(&service)?;
    // From here on only SYSTEM can stop or remove it (the MSI runs as SYSTEM).
    apply_security(&service)?;
    if start {
        service.start::<&str>(&[]).map_err(service_error)?;
    }
    Ok(())
}

/// Restart after 5 s, 15 s and 60 s, also when the agent exits with an error code.
fn apply_recovery(service: &windows_service::service::Service) -> Result<()> {
    let restart =
        |seconds| ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(seconds) };
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![restart(5), restart(15), restart(60)]),
        })
        .map_err(service_error)?;
    service.set_failure_actions_on_non_crash_failures(true).map_err(service_error)
}

/// Configure recovery and permissions on an already registered service. The MSI calls this because
/// Windows Installer opens services without SERVICE_START, which restart actions need.
pub fn configure_recovery() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(service_error)?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::CHANGE_CONFIG
                | ServiceAccess::START
                | ServiceAccess::READ_CONTROL
                | ServiceAccess::WRITE_DAC,
        )
        .map_err(service_error)?;
    apply_recovery(&service)?;
    apply_security(&service)
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// Replace the service DACL with SERVICE_SDDL.
fn apply_security(service: &windows_service::service::Service) -> Result<()> {
    use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
    use windows_sys::Win32::System::Services::SetServiceObjectSecurity;
    let sddl = wide(SERVICE_SDDL);
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: NUL-terminated SDDL; the descriptor is released with LocalFree after use.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut descriptor, std::ptr::null_mut())
            == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let applied = SetServiceObjectSecurity(service.raw_handle(), DACL_SECURITY_INFORMATION, descriptor);
        let error = std::io::Error::last_os_error();
        LocalFree(descriptor as HLOCAL);
        if applied == 0 {
            return Err(AgentError::Local(format!("service permissions not applied: {error}")));
        }
    }
    Ok(())
}

/// The service DACL as Windows reports it, in SDDL.
fn current_sddl(service: &windows_service::service::Service) -> Result<String> {
    use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
    use windows_sys::Win32::System::Services::QueryServiceObjectSecurity;
    let mut needed = 0u32;
    // SAFETY: a zero-length query only reports the size needed.
    unsafe {
        QueryServiceObjectSecurity(
            service.raw_handle(),
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if needed == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut buffer = vec![0u8; needed as usize];
    // SAFETY: buffer has the size the first call asked for.
    let read = unsafe {
        QueryServiceObjectSecurity(
            service.raw_handle(),
            DACL_SECURITY_INFORMATION,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if read == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: buffer holds a self-relative descriptor; the string is released with LocalFree.
    unsafe {
        if ConvertSecurityDescriptorToStringSecurityDescriptorW(
            buffer.as_mut_ptr().cast(),
            1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let length = (0..).take_while(|&index| *text.add(index) != 0).count();
        let sddl = String::from_utf16_lossy(std::slice::from_raw_parts(text, length));
        LocalFree(text as HLOCAL);
        Ok(sddl)
    }
}

fn set_automatic(service: &windows_service::service::Service) -> Result<()> {
    use windows_sys::Win32::System::Services::{ChangeServiceConfigW, SERVICE_AUTO_START, SERVICE_NO_CHANGE};
    let null = std::ptr::null();
    // SAFETY: every optional argument is null (unchanged); the handle has SERVICE_CHANGE_CONFIG.
    let changed = unsafe {
        ChangeServiceConfigW(
            service.raw_handle(),
            SERVICE_NO_CHANGE,
            SERVICE_AUTO_START,
            SERVICE_NO_CHANGE,
            null,
            null,
            std::ptr::null_mut(),
            null,
            null,
            null,
            null,
        )
    };
    if changed == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Automatic start, three restart actions (also on error exits) and the restricted DACL.
pub fn service_config_ok() -> Result<bool> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(service_error)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_CONFIG | ServiceAccess::READ_CONTROL)
        .map_err(service_error)?;
    let automatic = service.query_config().map_err(service_error)?.start_type == ServiceStartType::AutoStart;
    let restarts =
        service.get_failure_actions().map_err(service_error)?.actions.map_or(0, |actions| {
            actions.iter().filter(|action| action.action_type == ServiceActionType::Restart).count()
        });
    let on_errors = service.get_failure_actions_on_non_crash_failures().map_err(service_error)?;
    Ok(automatic && restarts >= 3 && on_errors && same_dacl(SERVICE_SDDL, &current_sddl(&service)?))
}

pub fn repair_service_config() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(service_error)?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_CONFIG
                | ServiceAccess::CHANGE_CONFIG
                | ServiceAccess::START
                | ServiceAccess::READ_CONTROL
                | ServiceAccess::WRITE_DAC,
        )
        .map_err(service_error)?;
    if service.query_config().map_err(service_error)?.start_type != ServiceStartType::AutoStart {
        set_automatic(&service)?;
    }
    apply_recovery(&service)?;
    apply_security(&service)
}

fn system_tool(name: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    root.join("System32").join(name)
}

fn schtasks(arguments: &[&std::ffi::OsStr]) -> Result<bool> {
    let status = std::process::Command::new(system_tool("schtasks.exe"))
        .args(arguments)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    Ok(status.success())
}

pub fn watchdog_task_present() -> Result<bool> {
    schtasks(&["/Query".as_ref(), "/TN".as_ref(), WATCHDOG_TASK.as_ref()])
}

/// Register (or replace) the SYSTEM watchdog task pointing at this executable.
pub fn install_watchdog_task() -> Result<()> {
    let executable = std::env::current_exe()?;
    let xml = watchdog_task_xml(&executable.to_string_lossy());
    // Task Scheduler reads the declared UTF-16 encoding, with a byte order mark.
    let bytes: Vec<u8> = [0xFF, 0xFE].into_iter().chain(xml.encode_utf16().flat_map(u16::to_le_bytes)).collect();
    let definition = data_dir().join("watchdog-task.xml");
    std::fs::write(&definition, bytes)?;
    let created = schtasks(&[
        "/Create".as_ref(),
        "/TN".as_ref(),
        WATCHDOG_TASK.as_ref(),
        "/XML".as_ref(),
        definition.as_os_str(),
        "/F".as_ref(),
    ]);
    let _ = std::fs::remove_file(&definition);
    if !created? {
        return Err(AgentError::Local("watchdog scheduled task was not created".into()));
    }
    Ok(())
}

pub fn remove_watchdog_task() -> Result<()> {
    if watchdog_task_present()?
        && !schtasks(&["/Delete".as_ref(), "/TN".as_ref(), WATCHDOG_TASK.as_ref(), "/F".as_ref()])?
    {
        return Err(AgentError::Local("watchdog scheduled task was not removed".into()));
    }
    Ok(())
}

/// Windows Installer holds this mutex while it installs, upgrades or removes anything.
fn installer_busy() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, GetLastError};
    use windows_sys::Win32::System::Threading::OpenMutexW;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    let name = wide("Global\\_MSIExecute");
    // SAFETY: NUL-terminated name; a returned handle is closed once.
    unsafe {
        let handle = OpenMutexW(SYNCHRONIZE, 0, name.as_ptr());
        if handle.is_null() {
            return GetLastError() == ERROR_ACCESS_DENIED;
        }
        CloseHandle(handle);
        true
    }
}

/// `openems-agent watchdog`, run by the scheduled task: put a disabled or stopped service back.
/// Events go to the pending file because the service may not be running to receive them.
pub fn run_watchdog() -> Result<()> {
    use crate::tamper::{TamperKind, append_pending};
    const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(service_error)?;
    let access =
        ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS | ServiceAccess::CHANGE_CONFIG | ServiceAccess::START;
    let service = match manager.open_service(SERVICE_NAME, access) {
        Ok(service) => Some(service),
        Err(windows_service::Error::Winapi(error)) if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST) => {
            None
        }
        Err(error) => return Err(service_error(error)),
    };
    let snapshot = match &service {
        Some(service) => Some(ServiceSnapshot {
            automatic: service.query_config().map_err(service_error)?.start_type == ServiceStartType::AutoStart,
            running: service.query_status().map_err(service_error)?.current_state != ServiceState::Stopped,
        }),
        None => None,
    };
    let pending = AgentConfig::from_file(&default_config_path())
        .ok()
        .map(|config| config.state_path.with_file_name("tamper-pending.json"));
    for (action, service) in
        watchdog_actions(snapshot, installer_busy()).into_iter().zip(std::iter::repeat(service.as_ref()))
    {
        let Some(service) = service else { break };
        let kind = match action {
            WatchdogAction::MakeAutomatic => TamperKind::ServiceConfigRestored,
            WatchdogAction::Start => TamperKind::ServiceStartedByWatchdog,
        };
        // Written before acting: a started service may read the file before a later write lands.
        if let Some(pending) = &pending {
            append_pending(pending, kind, kind.detail(), jiff::Timestamp::now())?;
        }
        match action {
            WatchdogAction::MakeAutomatic => set_automatic(service)?,
            WatchdogAction::Start => service.start::<&str>(&[]).map_err(service_error)?,
        }
    }
    Ok(())
}

/// Stop and remove the service, then clear only the managed hosts block.
pub fn uninstall(config: Option<PathBuf>, uninstall_code: Option<&str>) -> Result<()> {
    let config_path = config.unwrap_or_else(default_config_path);
    let agent_config = AgentConfig::from_file(&config_path)?;
    crate::removal::authorize_removal(&agent_config, uninstall_code)?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(service_error)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS)
        .map_err(service_error)?;
    stop_and_delete(service, || {
        clear_hosts(&agent_config.hosts_path)?;
        crate::trust::remove(Some(&config_path))?;
        remove_watchdog_task()
    })
}

/// Stop and delete the service when it exists (cleanup after a forced MSI removal).
pub fn remove_if_present() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(service_error)?;
    match manager.open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS)
    {
        Ok(service) => stop_and_delete(service, || Ok(())),
        Err(windows_service::Error::Winapi(error))
            if error.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST as i32) =>
        {
            Ok(())
        }
        Err(error) => Err(service_error(error)),
    }
}

/// Stop the service, run `before_delete` once it is stopped, then delete it.
fn stop_and_delete(
    service: windows_service::service::Service,
    before_delete: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if service.query_status().map_err(service_error)?.current_state != ServiceState::Stopped {
        service.stop().map_err(service_error)?;
        let deadline = Instant::now() + Duration::from_secs(45);
        while service.query_status().map_err(service_error)?.current_state != ServiceState::Stopped {
            if Instant::now() > deadline {
                return Err(AgentError::Local("service did not stop; inspect it before retrying".into()));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    before_delete()?;
    service.delete().map_err(service_error)?;
    drop(service);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_request_is_reported_as_pending_with_room_for_cleanup() {
        // Stop-Service fails if a stopping service still reports Running after its 2 s poll.
        let pending = stop_pending_status();
        assert_eq!(pending.current_state, ServiceState::StopPending);
        assert!(pending.controls_accepted.is_empty());
        assert!(pending.wait_hint >= Duration::from_secs(30));
        assert!(pending.checkpoint > 0);
    }
}
