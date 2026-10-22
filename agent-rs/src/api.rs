//! Endpoint channel client: no proxies, no redirects, bounded responses.

use crate::error::{AgentError, Result};
use serde_json::{Value, json};
use std::time::Duration;
use ureq::Agent;

const MAX_RESPONSE: u64 = 2 * 1024 * 1024;

pub struct ApiClient {
    agent: Agent,
    server: String,
}

pub struct Registration {
    pub client_id: String,
    pub device_token: String,
}

pub fn platform_name() -> &'static str {
    // Same values as Python's sys.platform, which the server already stores.
    if cfg!(windows) {
        "win32"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    }
}

impl ApiClient {
    pub fn new(server: &str) -> Self {
        let agent: Agent = Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(10)))
            .max_redirects(0)
            .proxy(None)
            .http_status_as_error(false)
            .user_agent(concat!("openems-agent/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        ApiClient { agent, server: server.trim_end_matches('/').to_owned() }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/fct/api/public/v1/{path}/", self.server)
    }

    /// The server's `detail` message, bounded and stripped of control characters for logs.
    fn reason(response: &mut ureq::http::Response<ureq::Body>) -> String {
        let body: Value = response.body_mut().with_config().limit(4096).read_json().unwrap_or(Value::Null);
        body.get("detail")
            .and_then(Value::as_str)
            .map(|detail| detail.chars().filter(|c| !c.is_control()).take(200).collect())
            .unwrap_or_default()
    }

    fn finish(response: std::result::Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> Result<Value> {
        let mut response = response.map_err(|error| AgentError::Transport(error.to_string()))?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(AgentError::Status { code: status, detail: Self::reason(&mut response) });
        }
        response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE)
            .read_json::<Value>()
            .map_err(|_| AgentError::Transport("invalid or oversized server response".into()))
    }

    pub fn post(&self, path: &str, payload: &Value, token: Option<&str>) -> Result<Value> {
        let mut request = self.agent.post(&self.url(path));
        if let Some(token) = token {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }
        Self::finish(request.send_json(payload))
    }

    pub fn get(&self, path: &str, query: &[(&str, &str)], token: Option<&str>) -> Result<Value> {
        let mut request = self.agent.get(&self.url(path));
        for (key, value) in query {
            request = request.query(*key, *value);
        }
        if let Some(token) = token {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }
        Self::finish(request.call())
    }

    pub fn register(
        &self,
        devid: &str,
        vdom: &str,
        invitation: Option<&str>,
        key: Option<&str>,
    ) -> Result<Registration> {
        let hostname = gethostname::gethostname().to_string_lossy().into_owned();
        let mut payload = json!({ "devid": devid, "os": platform_name(), "hostname": hostname, "vdom": vdom });
        if let Some(invitation) = invitation {
            payload["invitation"] = invitation.into();
        }
        if let Some(key) = key {
            payload["key"] = key.into();
        }
        let result = self.post("register", &payload, None)?;
        let device_token = result
            .get("device_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .map(str::to_owned)
            .or_else(|| key.map(str::to_owned))
            .ok_or_else(|| AgentError::Transport("registration returned no device credential".into()))?;
        let client_id = result
            .get("client_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| AgentError::Transport("registration returned no client identity".into()))?;
        Ok(Registration { client_id: client_id.to_owned(), device_token })
    }
}
