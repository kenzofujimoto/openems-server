//! Windows service host. Recovery (restart on failure) is configured by the installer.

use crate::app;
use crate::config::{AgentConfig, data_dir, default_config_path};
use crate::logging::file_logger;
use crate::runtime::StopSignal;
use std::ffi::OsString;
use std::sync::Arc;
use std::time::Duration;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "openems-agent";

define_windows_service!(ffi_service_main, service_main);

/// Hand the process to the Service Control Manager; returns when the service stops.
pub fn run_dispatcher() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
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
    let outcome = file_logger(&data_dir().join("agent.log")).and_then(|log| {
        let config = AgentConfig::from_file(&default_config_path());
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
