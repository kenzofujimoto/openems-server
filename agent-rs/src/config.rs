//! Agent configuration: the same strict agent.json the Python service reads.

use crate::error::{AgentError, Result};
use crate::fsutil::read_text_without_bom;
use crate::hosts::DEFAULT_HOSTS;
use serde_json::Value;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub struct AgentConfig {
    pub server: String,
    pub devid: String,
    pub vdom: String,
    pub hosts_path: PathBuf,
    pub interval: u64,
    pub dry_run: bool,
    pub block_page: bool,
    pub block_page_port: u16,
    pub block_page_https: bool,
    pub block_page_https_port: u16,
    pub authority_path: PathBuf,
    /// Serve DNS on loopback instead of writing the hosts file (Windows routes it via NRPT).
    pub dns_filter: bool,
    pub dns_port: u16,
    /// Block direct DNS, DoT and known DoH endpoints and set browser DoH policies; needs dns_filter.
    pub anti_bypass: bool,
    pub invitation: Option<String>,
    pub device_token: Option<String>,
    pub state_path: PathBuf,
    pub allow_insecure_http: bool,
}

/// ProgramData\openems on Windows, /etc/openems elsewhere.
pub fn data_dir() -> PathBuf {
    if cfg!(windows) {
        let base = std::env::var_os("PROGRAMDATA").map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
        base.join("openems")
    } else {
        PathBuf::from("/var/lib/openems")
    }
}

pub fn default_config_path() -> PathBuf {
    if cfg!(windows) { data_dir().join("agent.json") } else { PathBuf::from("/etc/openems/agent.json") }
}

impl AgentConfig {
    pub fn new(server: impl Into<String>, devid: impl Into<String>) -> Self {
        AgentConfig {
            server: server.into(),
            devid: devid.into(),
            vdom: "Default".into(),
            hosts_path: PathBuf::from(DEFAULT_HOSTS),
            interval: 15,
            dry_run: false,
            block_page: false,
            block_page_port: 80,
            block_page_https: false,
            block_page_https_port: 443,
            authority_path: data_dir().join("https").join("authority.json"),
            dns_filter: false,
            dns_port: 53,
            anti_bypass: false,
            invitation: None,
            device_token: None,
            state_path: data_dir().join("state.json"),
            allow_insecure_http: false,
        }
    }

    /// Read agent.json; unknown keys and loosely typed values are rejected.
    pub fn from_file(path: &Path) -> Result<Self> {
        let text = read_text_without_bom(path)
            .map_err(|error| AgentError::Config(format!("cannot read configuration: {error}")))?;
        let value: Value =
            serde_json::from_str(&text).map_err(|_| AgentError::Config("configuration is not valid JSON".into()))?;
        let Value::Object(data) = value else {
            return Err(AgentError::Config("agent configuration must be an object".into()));
        };
        const TEXT: [&str; 8] =
            ["server", "devid", "vdom", "hosts_path", "state_path", "invitation", "device_token", "authority_path"];
        const FLAGS: [&str; 6] =
            ["block_page", "dry_run", "allow_insecure_http", "block_page_https", "dns_filter", "anti_bypass"];
        const NUMBERS: [&str; 4] = ["interval", "block_page_port", "block_page_https_port", "dns_port"];
        if data.keys().any(|key| {
            !TEXT.contains(&key.as_str()) && !FLAGS.contains(&key.as_str()) && !NUMBERS.contains(&key.as_str())
        }) {
            return Err(AgentError::Config("unknown agent configuration option".into()));
        }
        let text = |key: &str| -> Result<Option<String>> {
            match data.get(key) {
                None => Ok(None),
                Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.clone())),
                Some(_) => Err(AgentError::Config(format!("invalid configuration option: {key}"))),
            }
        };
        let flag = |key: &str| -> Result<bool> {
            match data.get(key) {
                None => Ok(false),
                Some(Value::Bool(value)) => Ok(*value),
                Some(_) => Err(AgentError::Config(format!("invalid configuration option: {key}"))),
            }
        };
        let number = |key: &str, default: u64| -> Result<u64> {
            match data.get(key) {
                None => Ok(default),
                Some(Value::Number(value)) if value.is_u64() => Ok(value.as_u64().unwrap_or(default)),
                Some(_) => Err(AgentError::Config(format!("invalid configuration option: {key}"))),
            }
        };
        let (Some(server), Some(devid)) = (text("server")?, text("devid")?) else {
            return Err(AgentError::Config("server and device identity are required".into()));
        };
        let port = number("block_page_port", 80)?;
        let mut config = AgentConfig::new(server, devid);
        config.vdom = text("vdom")?.unwrap_or(config.vdom);
        config.hosts_path = text("hosts_path")?.map_or(config.hosts_path, PathBuf::from);
        config.state_path = text("state_path")?.map_or_else(|| path.with_file_name("state.json"), PathBuf::from);
        config.invitation = text("invitation")?;
        config.device_token = text("device_token")?;
        config.interval = number("interval", 15)?;
        config.block_page = flag("block_page")?;
        config.block_page_https = flag("block_page_https")?;
        config.authority_path =
            text("authority_path")?.map_or_else(|| path.with_file_name("https").join("authority.json"), PathBuf::from);
        config.block_page_https_port = u16::try_from(number("block_page_https_port", 443)?)
            .ok()
            .filter(|port| *port > 0)
            .ok_or_else(|| AgentError::Config("HTTPS block page port is out of range".into()))?;
        config.dns_filter = flag("dns_filter")?;
        config.anti_bypass = flag("anti_bypass")?;
        config.dns_port = u16::try_from(number("dns_port", 53)?)
            .ok()
            .filter(|port| *port > 0)
            .ok_or_else(|| AgentError::Config("DNS port is out of range".into()))?;
        config.dry_run = flag("dry_run")?;
        config.allow_insecure_http = flag("allow_insecure_http")?;
        config.block_page_port = u16::try_from(port)
            .ok()
            .filter(|port| *port > 0)
            .ok_or_else(|| AgentError::Config("block page port is out of range".into()))?;
        config.validate()?;
        Ok(config)
    }

    /// Port of `_validate_server`: an origin only, HTTPS unless loopback or explicitly allowed.
    pub fn validate(&mut self) -> Result<()> {
        let origin = parse_origin(&self.server)?;
        let loopback = origin.host == "localhost" || origin.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
        let secure = origin.scheme == "https" || (origin.scheme == "http" && (loopback || self.allow_insecure_http));
        if !secure {
            return Err(AgentError::Config("HTTPS is required for remote endpoint connections".into()));
        }
        if self.interval == 0 {
            return Err(AgentError::Config("interval must be positive".into()));
        }
        if self.block_page_https
            && (!self.block_page
                || self.dry_run
                || self.block_page_https_port == 0
                || self.block_page_https_port == self.block_page_port)
        {
            return Err(AgentError::Config(
                "HTTPS block page requires block_page, distinct ports and enforcement mode".into(),
            ));
        }
        if self.dns_filter && (self.dry_run || self.dns_port == 0) {
            return Err(AgentError::Config("DNS filter requires enforcement mode and a nonzero port".into()));
        }
        if self.anti_bypass && !self.dns_filter {
            return Err(AgentError::Config("anti-bypass requires the DNS filter".into()));
        }
        if self.devid.trim().is_empty() {
            return Err(AgentError::Config("devid is required".into()));
        }
        self.server = self.server.trim_end_matches('/').to_owned();
        Ok(())
    }

    /// agent.json representation; the device token is never written here (it lives in state).
    pub fn to_json(&self) -> Value {
        let mut data = serde_json::json!({
            "server": self.server,
            "devid": self.devid,
            "vdom": self.vdom,
            "hosts_path": self.hosts_path.to_string_lossy(),
            "state_path": self.state_path.to_string_lossy(),
            "interval": self.interval,
            "block_page": self.block_page,
            "block_page_port": self.block_page_port,
            "block_page_https": self.block_page_https,
            "block_page_https_port": self.block_page_https_port,
            "authority_path": self.authority_path.to_string_lossy(),
            "dns_filter": self.dns_filter,
            "dns_port": self.dns_port,
            "anti_bypass": self.anti_bypass,
            "allow_insecure_http": self.allow_insecure_http,
        });
        if let Some(invitation) = &self.invitation {
            data["invitation"] = invitation.clone().into();
        }
        data
    }

    /// Write a protected agent.json that `from_file` accepts.
    pub fn write_file(&self, path: &Path) -> Result<()> {
        let encoded =
            serde_json::to_vec_pretty(&self.to_json()).map_err(|error| AgentError::Local(error.to_string()))?;
        if path.parent() == Some(data_dir().as_path()) {
            // The service location may predate this install; take it over before writing secrets.
            std::fs::create_dir_all(data_dir())?;
            crate::fsutil::secure_directory(&data_dir())?;
        }
        crate::fsutil::atomic_write(path, &encoded, None, true)
    }
}

struct Origin {
    scheme: String,
    host: String,
}

fn parse_origin(url: &str) -> Result<Origin> {
    let bad = || AgentError::Config("server must be an origin without credentials, query or path".into());
    let (scheme, rest) = url.split_once("://").ok_or_else(bad)?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(bad());
    }
    let split = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(split);
    if !(tail.is_empty() || tail == "/") || authority.contains('@') || authority.is_empty() {
        return Err(bad());
    }
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        bracketed.split_once(']').map(|(host, _)| host).ok_or_else(bad)?
    } else {
        authority
            .rsplit_once(':')
            .map_or(authority, |(host, port)| if port.chars().all(|c| c.is_ascii_digit()) { host } else { authority })
    };
    if host.is_empty() {
        return Err(bad());
    }
    Ok(Origin { scheme, host: host.to_ascii_lowercase() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validated(server: &str, insecure: bool) -> Result<String> {
        let mut config = AgentConfig::new(server, "pc");
        config.allow_insecure_http = insecure;
        config.validate().map(|()| config.server)
    }

    #[test]
    fn servers_must_be_secure_origins() {
        assert_eq!(validated("https://ems.example.com/", false).unwrap(), "https://ems.example.com");
        assert!(validated("http://127.0.0.1:8013", false).is_ok());
        assert!(validated("http://localhost:8013", false).is_ok());
        assert!(validated("http://[::1]:8013", false).is_ok());
        assert!(validated("http://ems.example.com", false).is_err());
        assert!(validated("http://ems.example.com", true).is_ok());
        for bad in [
            "https://user:pw@ems.example.com",
            "https://ems.example.com/path",
            "https://ems.example.com?x=1",
            "ftp://ems",
            "ems.example.com",
        ] {
            assert!(validated(bad, false).is_err(), "{bad}");
        }
    }

    #[test]
    fn written_configuration_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("agent.json");
        let mut config = AgentConfig::new("https://ems.example.com", "PC1");
        config.invitation = Some("invite".into());
        config.device_token = Some("secret-token".into());
        config.state_path = dir.path().join("state.json");
        config.write_file(&path).unwrap();
        assert!(!std::fs::read_to_string(&path).unwrap().contains("secret-token"));
        let loaded = AgentConfig::from_file(&path).unwrap();
        assert_eq!(loaded, AgentConfig { device_token: None, ..config });
    }

    #[test]
    fn configuration_files_are_strict() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.json");
        std::fs::write(
            &path,
            "\u{feff}{\"server\": \"https://ems.example.com\", \"devid\": \"PC1\", \"interval\": 30}",
        )
        .unwrap();
        let config = AgentConfig::from_file(&path).unwrap();
        assert_eq!((config.interval, config.state_path.clone()), (30, dir.path().join("state.json")));
        for bad in [
            r#"{"server": "https://e.com", "devid": "PC1", "extra": 1}"#,
            r#"{"server": "https://e.com", "devid": "PC1", "interval": "30"}"#,
            r#"{"server": "https://e.com", "devid": 5}"#,
            r#"{"server": "https://e.com", "devid": "PC1", "dry_run": "yes"}"#,
            r#"{"server": "https://e.com", "devid": "PC1", "block_page_port": 70000}"#,
            r#"[]"#,
            r#"{"devid": "PC1"}"#,
        ] {
            std::fs::write(&path, bad).unwrap();
            let error = AgentConfig::from_file(&path).unwrap_err();
            assert!(error.to_string().contains("configuration"), "{bad}: {error}");
        }
    }
}
