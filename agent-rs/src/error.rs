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
    /// The server answered with a non-success HTTP status.
    Status(u16),
    /// Network or TLS failure talking to the server.
    Transport(String),
    /// Hosts file, process or other local operation failed.
    Local(String),
    Io(std::io::Error),
}

impl AgentError {
    /// Short category for logs, mirroring the Python agent's exception names.
    pub fn kind(&self) -> &'static str {
        match self {
            AgentError::Config(_) => "ConfigError",
            AgentError::Policy(_) => "PolicyError",
            AgentError::State(_) => "StateError",
            AgentError::Status(_) => "HTTPError",
            AgentError::Transport(_) => "TransportError",
            AgentError::Local(_) => "LocalError",
            AgentError::Io(_) => "OSError",
        }
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentError::Config(message) => write!(f, "invalid configuration: {message}"),
            AgentError::Policy(message) => write!(f, "invalid policy: {message}"),
            AgentError::State(message) => write!(f, "endpoint state error: {message}"),
            AgentError::Status(code) => write!(f, "server returned HTTP {code}"),
            AgentError::Transport(message) => write!(f, "server unreachable: {message}"),
            AgentError::Local(message) => write!(f, "{message}"),
            AgentError::Io(error) => write!(f, "I/O error: {error}"),
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
