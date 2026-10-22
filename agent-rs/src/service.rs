//! Windows service host and registration with automatic start and recovery.

use crate::app;
use crate::config::{AgentConfig, data_dir, default_config_path};
use crate::error::{AgentError, Result};
use crate::hosts::clear_hosts;
use crate::logging::file_logger;
use crate::runtime::StopSignal;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
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
    let config_path = CONFIG_PATH.get().cloned().unwrap_or_else(default_config_path);
    let outcome = file_logger(&data_dir().join("agent.log")).and_then(|log| {
        let config = AgentConfig::from_file(&config_path);
        if let Err(error) = &config {
            log(&format!("configuration rejected: {error}"));
        }
        let result = config.and_then(|config| app::run(config, Arc::clone(&log), Arc::clone(&stop)));
        if let Err(error) = &result {
            log(&format!("agent stopped with an error ({})", error.kind()));
        }
        result
    });
    // A non-zero exit lets the configured failure actions restart the agent.
    let exit = if outcome.is_ok() { ServiceExitCode::Win32(0) } else { ServiceExitCode::ServiceSpecific(1) };
    let _ = handle.set_service_status(status(ServiceState::Stopped, exit));
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
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS)
        .map_err(service_error)?;
    service.set_description(DESCRIPTION).map_err(service_error)?;
    apply_recovery(&service)?;
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

/// Configure recovery on an already registered service. The MSI calls this because
/// Windows Installer opens services without SERVICE_START, which restart actions need.
pub fn configure_recovery() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(service_error)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .map_err(service_error)?;
    apply_recovery(&service)
}

/// Stop and remove the service, then clear only the managed hosts block.
pub fn uninstall(config: Option<PathBuf>) -> Result<()> {
    let config_path = config.unwrap_or_else(default_config_path);
    let hosts_path = AgentConfig::from_file(&config_path)?.hosts_path;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(service_error)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS)
        .map_err(service_error)?;
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
    service.delete().map_err(service_error)?;
    drop(service);
    clear_hosts(&hosts_path)?;
    Ok(())
}
