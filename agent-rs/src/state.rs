//! Persisted endpoint identity and last valid policy, in the Python agent's format
//! so an existing installation upgrades without enrolling again.

use crate::error::{AgentError, Result};
use crate::fsutil::{atomic_write, read_text_without_bom};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EndpointState {
    pub server: String,
    pub devid: String,
    pub client_id: Option<String>,
    pub device_token: Option<String>,
    pub profile: Option<Value>,
}

const UNTRUSTED: &str = "cannot load endpoint state; preserve hosts and repair state";

impl EndpointState {
    /// Load state for this server and device; any inconsistency stops the agent
    /// rather than silently enrolling again or enforcing an unverified policy.
    pub fn load(path: &Path, server: &str, devid: &str) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let text = read_text_without_bom(path).map_err(|_| AgentError::State(UNTRUSTED.into()))?;
        let state: EndpointState = serde_json::from_str(&text).map_err(|_| AgentError::State(UNTRUSTED.into()))?;
        if state.server != server || state.devid != devid {
            return Err(AgentError::State("cached state belongs to another endpoint or server".into()));
        }
        Ok(Some(state))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let encoded = serde_json::to_vec(self).map_err(|error| AgentError::Local(error.to_string()))?;
        atomic_write(path, &encoded, None, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_rejects_foreign_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        assert_eq!(EndpointState::load(&path, "https://e", "pc").unwrap(), None);
        let state = EndpointState {
            server: "https://e".into(),
            devid: "pc".into(),
            client_id: Some("c".into()),
            ..Default::default()
        };
        state.save(&path).unwrap();
        assert_eq!(EndpointState::load(&path, "https://e", "pc").unwrap(), Some(state));
        assert!(EndpointState::load(&path, "https://other", "pc").is_err());
        std::fs::write(&path, "{broken").unwrap();
        assert!(matches!(EndpointState::load(&path, "https://e", "pc"), Err(AgentError::State(_))));
    }
}
