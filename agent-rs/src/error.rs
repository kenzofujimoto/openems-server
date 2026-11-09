use std::fmt;

/// Every failure the agent reports. Messages never include credentials.
#[derive(Debug)]
pub enum AgentError {
    /// Invalid configuration file or command-line options.
    Config(String),
    /// Policy payload failed validation or integrity checks.
    Policy(String),
    /// The cached endpoint state cannot be trusted.
    State(String),
    /// The server answered with a non-success HTTP status and its stated reason.
    Status {
        code: u16,
        detail: String,
    },
    /// Network or TLS failure talking to the server.
    Transport(String),
    /// Hosts file, process or other local operation failed.
    Local(String),
    Io(std::io::Error),
    Diagnosed(Box<DiagnosedError>),
}

#[derive(Debug)]
pub struct DiagnosedError {
    error: AgentError,
    steps: Vec<Diagnostic>,
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(windows), allow(dead_code))] // Windows adapters use the transport and application stages.
pub(crate) enum Stage {
    PolicyValidation,
    ControlApply,
    UsbReconcile,
    AppReconcile,
    ControlEvents,
    Hosts,
    ProcessEnumerate,
    ProcessSelect,
    ProcessTerminate,
    EndpointState,
    ControlRequest,
    ControlStaging,
    ControlSpawn,
    ControlWait,
    ControlTimeout,
    ControlStop,
    ControlInput,
    ControlOutput,
    ControlStderr,
    ControlResponse,
    ControlCleanup,
    AppRequest,
    AppJournal,
    AppInventory,
    AppWdacQuery,
    AppSampleDiscovery,
    AppWdacGenerate,
    AppWdacApply,
    AppWdacVerify,
    AppWdacRemove,
    AppFirewall,
    AppExecutionEvents,
}

impl Stage {
    fn as_str(self) -> &'static str {
        match self {
            Self::PolicyValidation => "policy_validation",
            Self::ControlApply => "control_apply",
            Self::UsbReconcile => "usb_reconcile",
            Self::AppReconcile => "app_reconcile",
            Self::ControlEvents => "control_events",
            Self::Hosts => "hosts",
            Self::ProcessEnumerate => "process_enumerate",
            Self::ProcessSelect => "process_select",
            Self::ProcessTerminate => "process_terminate",
            Self::EndpointState => "endpoint_state",
            Self::ControlRequest => "control_request",
            Self::ControlStaging => "control_staging",
            Self::ControlSpawn => "control_spawn",
            Self::ControlWait => "control_wait",
            Self::ControlTimeout => "control_timeout",
            Self::ControlStop => "control_stop",
            Self::ControlInput => "control_input",
            Self::ControlOutput => "control_output",
            Self::ControlStderr => "control_stderr",
            Self::ControlResponse => "control_response",
            Self::ControlCleanup => "control_cleanup",
            Self::AppRequest => "app_request",
            Self::AppJournal => "app_journal",
            Self::AppInventory => "app_inventory",
            Self::AppWdacQuery => "app_wdac_query",
            Self::AppSampleDiscovery => "app_sample_discovery",
            Self::AppWdacGenerate => "app_wdac_generate",
            Self::AppWdacApply => "app_wdac_apply",
            Self::AppWdacVerify => "app_wdac_verify",
            Self::AppWdacRemove => "app_wdac_remove",
            Self::AppFirewall => "app_firewall",
            Self::AppExecutionEvents => "app_execution_events",
        }
    }

    #[cfg(windows)]
    pub(crate) fn from_app_name(name: &str) -> Option<Self> {
        [
            Self::AppRequest,
            Self::AppJournal,
            Self::AppInventory,
            Self::AppWdacQuery,
            Self::AppSampleDiscovery,
            Self::AppWdacGenerate,
            Self::AppWdacApply,
            Self::AppWdacVerify,
            Self::AppWdacRemove,
            Self::AppFirewall,
            Self::AppExecutionEvents,
        ]
        .into_iter()
        .find(|stage| stage.as_str() == name)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Diagnostic {
    stage: Stage,
    os_code: Option<i32>,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.stage.as_str())?;
        if let Some(code) = self.os_code {
            write!(f, ":{code}")?;
        }
        Ok(())
    }
}

impl AgentError {
    /// Short category for logs, mirroring the Python agent's exception names.
    /// Log-safe summary: the HTTP status and the server's reason, otherwise only the category.
    pub fn summary(&self) -> String {
        match self {
            AgentError::Status { code, detail } if detail.is_empty() => format!("HTTP {code}"),
            AgentError::Status { code, detail } => format!("HTTP {code}: {detail}"),
            AgentError::Diagnosed(context) => context.error.summary(),
            other => other.kind().to_owned(),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            AgentError::Config(_) => "ConfigError",
            AgentError::Policy(_) => "PolicyError",
            AgentError::State(_) => "StateError",
            AgentError::Status { .. } => "HTTPError",
            AgentError::Transport(_) => "TransportError",
            AgentError::Local(_) => "LocalError",
            AgentError::Io(_) => "OSError",
            AgentError::Diagnosed(context) => context.error.kind(),
        }
    }

    pub(crate) fn at(self, stage: Stage) -> Self {
        let os_code = match &self {
            Self::Io(error) => error.raw_os_error(),
            _ => None,
        };
        self.at_code(stage, os_code)
    }

    pub(crate) fn at_code(self, stage: Stage, os_code: Option<i32>) -> Self {
        self.with_steps(&[Diagnostic { stage, os_code }])
    }

    pub(crate) fn at_if_missing(self, stage: Stage) -> Self {
        if self.diagnostics().is_empty() { self.at(stage) } else { self }
    }

    /// Preserve the winning error. Only the related failure's safe metadata is carried forward.
    pub(crate) fn with_related(self, related: &Self) -> Self {
        self.with_steps(related.diagnostics())
    }

    fn with_steps(self, steps: &[Diagnostic]) -> Self {
        match self {
            Self::Diagnosed(mut context) => {
                context.steps.extend_from_slice(steps);
                Self::Diagnosed(context)
            }
            error => Self::Diagnosed(Box::new(DiagnosedError { error, steps: steps.to_vec() })),
        }
    }

    pub(crate) fn diagnostics(&self) -> &[Diagnostic] {
        match self {
            Self::Diagnosed(context) => &context.steps,
            _ => &[],
        }
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentError::Config(message) => write!(f, "invalid configuration: {message}"),
            AgentError::Policy(message) => write!(f, "invalid policy: {message}"),
            AgentError::State(message) => write!(f, "endpoint state error: {message}"),
            AgentError::Status { code, detail } => write!(f, "server returned HTTP {code}: {detail}"),
            AgentError::Transport(message) => write!(f, "server unreachable: {message}"),
            AgentError::Local(message) => write!(f, "{message}"),
            AgentError::Io(error) => write!(f, "I/O error: {error}"),
            AgentError::Diagnosed(context) => context.error.fmt(f),
        }
    }
}

impl std::error::Error for AgentError {}

impl From<std::io::Error> for AgentError {
    fn from(error: std::io::Error) -> Self {
        AgentError::Io(error)
    }
}

pub type Result<T> = std::result::Result<T, AgentError>;
