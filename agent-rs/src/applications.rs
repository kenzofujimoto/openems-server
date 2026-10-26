//! Execution and network controls, separate from the process-name termination fallback.

use crate::error::Result;
pub use crate::windows_control::Event;
use crate::windows_control::{self as adapter, identifier, invalid, text};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const SCRIPT: &str = include_str!("../../deploy/agent-applications.ps1");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Hash,
    Publisher,
    Path,
    Name,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub kind: Kind,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_path: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub blocked: Vec<String>,
    #[serde(default)]
    pub execution_rules: Vec<Rule>,
    #[serde(default)]
    pub network_blocked: Vec<String>,
}

pub fn absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    text(path, 2048)
        && !path.chars().any(|c| "*?\"<>|%".contains(c))
        && !path.split(['\\', '/']).any(|part| matches!(part, "." | ".."))
        && ((path.starts_with('/') && !path.starts_with("//"))
            || (bytes.len() > 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && matches!(bytes[2], b'\\' | b'/')))
}

fn protected_name(name: &str) -> bool {
    [
        "openems-agent.exe",
        "openems-session.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "winlogon.exe",
        "csrss.exe",
        "smss.exe",
        "powershell.exe",
        "citool.exe",
    ]
    .iter()
    .any(|protected| name.eq_ignore_ascii_case(protected))
}

fn protected_path(path: &str) -> bool {
    let lower = path.replace('/', "\\").to_ascii_lowercase();
    lower.contains("\\windows\\") || lower.rsplit('\\').next().is_some_and(protected_name)
}

pub fn validate(value: Option<&Value>) -> Result<Policy> {
    let normalized =
        crate::policy::validate_policy(&json!({"app_control":value.cloned().unwrap_or_else(|| json!({}))}))?;
    let mut policy: Policy = serde_json::from_value(normalized["app_control"].clone())
        .map_err(|_| invalid("invalid application controls"))?;
    if policy.blocked.iter().any(|name| protected_name(name)) {
        return Err(invalid("core Windows and agent components cannot be terminated"));
    }
    if policy.execution_rules.len() > 256 || policy.network_blocked.len() > 256 {
        return Err(invalid("too many application rules"));
    }
    let mut ids = std::collections::HashSet::new();
    for rule in &mut policy.execution_rules {
        if !identifier(&rule.id) || !ids.insert(rule.id.clone()) || !text(&rule.value, 2048) {
            return Err(invalid("invalid or duplicate execution rule"));
        }
        if rule.sample_path.as_deref().is_some_and(|path| !absolute_path(path) || protected_path(path)) {
            return Err(invalid("invalid or protected execution sample"));
        }
        match rule.kind {
            Kind::Hash => {
                if rule.value.len() != 64 || !rule.value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(invalid("execution hash must be SHA-256"));
                }
                rule.value = rule.value.to_ascii_lowercase();
            }
            Kind::Publisher => {
                if rule.value.to_ascii_lowercase().contains("microsoft") {
                    return Err(invalid("a broad Microsoft publisher deny would block Windows components"));
                }
            }
            Kind::Path => {
                if !absolute_path(&rule.value) || protected_path(&rule.value) {
                    return Err(invalid("invalid or protected execution path"));
                }
            }
            Kind::Name => {
                rule.value = crate::policy::normalize_process(&rule.value)?;
                if protected_name(&rule.value) {
                    return Err(invalid("core Windows and agent components cannot be denied"));
                }
            }
        }
    }
    for path in &policy.network_blocked {
        if !absolute_path(path) || protected_path(path) {
            return Err(invalid("invalid or protected network application path"));
        }
    }
    policy.network_blocked.sort_by_key(|path| path.to_ascii_lowercase());
    policy.network_blocked.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    Ok(policy)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Application {
    pub name: String,
    pub path: String,
    pub sha256: String,
    pub publisher: String,
    pub version: String,
    pub running: bool,
    #[serde(skip_serializing)]
    pub signature_valid: bool,
    #[serde(skip_serializing)]
    pub original_name: String,
}

pub fn resolve_rules(policy: &Policy, inventory: &[Application]) -> Result<Vec<Rule>> {
    policy
        .execution_rules
        .iter()
        .cloned()
        .map(|mut rule| {
            if rule.kind == Kind::Path {
                return Ok(rule);
            }
            let sample = inventory
                .iter()
                .find(|application| {
                    rule.sample_path.as_ref().is_none_or(|path| path.eq_ignore_ascii_case(&application.path))
                        && match rule.kind {
                            Kind::Hash => application.sha256.eq_ignore_ascii_case(&rule.value),
                            Kind::Publisher => {
                                application.signature_valid && application.publisher.eq_ignore_ascii_case(&rule.value)
                            }
                            Kind::Name => application.original_name.eq_ignore_ascii_case(&rule.value),
                            Kind::Path => false,
                        }
                })
                .ok_or_else(|| invalid("execution rule has no matching verified local sample"))?;
            if protected_path(&sample.path) || protected_name(&sample.original_name) {
                return Err(invalid("execution sample targets a protected system component"));
            }
            rule.sample_path = Some(sample.path.clone());
            Ok(rule)
        })
        .collect()
}

pub fn journal_path(state: &Path) -> PathBuf {
    state.with_file_name("application-control.json")
}

pub fn inventory(_state: &Path) -> Result<Vec<Application>> {
    let result = adapter::run(SCRIPT, &json!({"mode":"inventory"}))?;
    serde_json::from_value(result["inventory"].clone()).map_err(|_| invalid("invalid application inventory"))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Outcome {
    pub inventory: Vec<Application>,
    pub events: Vec<Event>,
    pub capabilities: Vec<String>,
}

pub fn capabilities() -> Vec<String> {
    if cfg!(windows) {
        let mut capabilities = vec!["app-control:network".into(), "app-control:firewall".into()];
        if std::env::var_os("SystemRoot").is_some_and(|root| Path::new(&root).join("System32/CiTool.exe").is_file()) {
            capabilities.push("app-control:wdac".into());
        }
        capabilities
    } else {
        Vec::new()
    }
}

pub fn reconcile(policy: &Policy, state: &Path) -> Result<Outcome> {
    let journal = journal_path(state);
    if policy.execution_rules.is_empty() && policy.network_blocked.is_empty() && !journal.exists() {
        return Ok(Outcome::default());
    }
    #[cfg(windows)]
    crate::authority::require_system()?;
    let result =
        adapter::run(SCRIPT, &json!({"mode":"apply", "state_path":adapter::path(&journal)?, "policy":policy}))?;
    serde_json::from_value(result).map_err(|_| invalid("invalid application control result"))
}

pub fn cleanup(state: &Path) -> Result<()> {
    let journal = journal_path(state);
    if !journal.exists() {
        return Ok(());
    }
    #[cfg(windows)]
    crate::authority::require_system()?;
    adapter::run(SCRIPT, &json!({"mode":"cleanup", "state_path":adapter::path(&journal)?}))?;
    Ok(())
}
