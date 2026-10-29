//! USB mass-storage decisions. HID and system disks are never enforcement targets.

use crate::error::Result;
pub use crate::windows_control::Event;
use crate::windows_control::{self as adapter, identifier, invalid, text};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const SCRIPT: &str = include_str!("../../deploy/agent-usb.ps1");

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    #[default]
    Allow,
    Block,
    ReadOnly,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub default_action: Action,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

pub fn validate(value: Option<&Value>) -> Result<Policy> {
    let normalized =
        crate::policy::validate_policy(&json!({"usb_control":value.cloned().unwrap_or_else(|| json!({}))}))?;
    let mut policy: Policy = serde_json::from_value(normalized["usb_control"].clone())
        .map_err(|_| invalid("invalid USB control settings"))?;
    if policy.rules.len() > 256 {
        return Err(invalid("too many USB rules"));
    }
    let mut ids = std::collections::HashSet::new();
    for rule in &mut policy.rules {
        if !identifier(&rule.id) || !ids.insert(rule.id.clone()) {
            return Err(invalid("invalid or duplicate USB rule id"));
        }
        if rule.class.as_deref().is_some_and(|class| class != "storage") {
            return Err(invalid("only storage may be controlled by USB rules"));
        }
        if [&rule.vid, &rule.pid, &rule.serial, &rule.instance_id, &rule.class].iter().all(|value| value.is_none()) {
            return Err(invalid("a USB rule needs a selector"));
        }
        for value in [&mut rule.vid, &mut rule.pid].into_iter().flatten() {
            if value.len() != 4 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(invalid("USB VID/PID must be four hexadecimal digits"));
            }
            *value = value.to_ascii_lowercase();
        }
        if rule.serial.as_deref().is_some_and(|value| !text(value, 512))
            || rule.instance_id.as_deref().is_some_and(|value| !text(value, 512))
        {
            return Err(invalid("invalid USB serial or instance id"));
        }
    }
    Ok(policy)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Device {
    pub instance_id: String,
    pub vid: String,
    pub pid: String,
    pub manufacturer: String,
    pub product: String,
    pub serial: String,
    pub class: String,
    pub drive_letters: Vec<String>,
    pub present: bool,
    pub first_seen: String,
    pub last_seen: String,
    #[serde(skip_serializing)]
    pub disk_number: Option<u32>,
    #[serde(skip_serializing)]
    pub disk_unique_id: String,
    #[serde(skip_serializing)]
    pub is_boot: bool,
    #[serde(skip_serializing)]
    pub is_system: bool,
}

pub fn decide(policy: &Policy, device: &Device) -> Action {
    if device.class != "storage" || device.is_boot || device.is_system {
        return Action::Allow;
    }
    policy
        .rules
        .iter()
        .find(|rule| {
            [
                (&rule.class, &device.class),
                (&rule.vid, &device.vid),
                (&rule.pid, &device.pid),
                (&rule.serial, &device.serial),
                (&rule.instance_id, &device.instance_id),
            ]
            .iter()
            .all(|(wanted, actual)| wanted.as_ref().is_none_or(|wanted| wanted.eq_ignore_ascii_case(actual)))
        })
        .map_or(policy.default_action, |rule| rule.action)
}

pub fn merge_history(previous: &[Device], observed: Vec<Device>, now: &str) -> Vec<Device> {
    let mut devices: std::collections::BTreeMap<String, Device> = previous
        .iter()
        .take(512)
        .cloned()
        .map(|mut device| {
            device.present = false;
            (device.instance_id.to_ascii_lowercase(), device)
        })
        .collect();
    for mut device in observed.into_iter().take(512) {
        let id = device.instance_id.to_ascii_lowercase();
        device.first_seen = devices.get(&id).map_or_else(|| now.to_owned(), |old| old.first_seen.clone());
        device.last_seen = now.to_owned();
        device.present = true;
        devices.insert(id, device);
    }
    let mut devices: Vec<_> = devices.into_values().collect();
    devices.sort_by(|a, b| b.present.cmp(&a.present).then_with(|| b.last_seen.cmp(&a.last_seen)));
    devices.truncate(512);
    devices
}

pub fn journal_path(state: &Path) -> PathBuf {
    state.with_file_name("usb-control.json")
}

pub fn inventory(state: &Path) -> Result<Vec<Device>> {
    let result = adapter::run_background(SCRIPT, &json!({"mode":"inventory"}))?;
    let observed: Vec<Device> =
        serde_json::from_value(result["inventory"].clone()).map_err(|_| invalid("invalid USB inventory"))?;
    let history = state.with_file_name("usb-inventory.json");
    let previous = match std::fs::read(&history) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| invalid("invalid USB inventory cache"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    let devices = merge_history(&previous, observed, &jiff::Timestamp::now().to_string());
    let encoded = serde_json::to_vec(&devices).map_err(|_| invalid("invalid USB inventory"))?;
    crate::fsutil::atomic_write(&history, &encoded, None, true)?;
    Ok(devices)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Outcome {
    pub inventory: Vec<Device>,
    pub events: Vec<Event>,
    pub capabilities: Vec<String>,
}

pub fn capabilities() -> Vec<String> {
    if cfg!(windows) { vec!["usb-control:v1".into(), "usb:storage".into(), "usb:polling".into()] } else { Vec::new() }
}

pub fn reconcile(policy: &Policy, state: &Path) -> Result<Outcome> {
    let journal = journal_path(state);
    if policy.default_action == Action::Allow && policy.rules.is_empty() && !journal.exists() {
        return Ok(Outcome::default());
    }
    #[cfg(windows)]
    crate::authority::require_system()?;
    let result =
        adapter::run(SCRIPT, &json!({"mode":"apply", "state_path":adapter::path(&journal)?, "policy":policy}))?;
    serde_json::from_value(result).map_err(|_| invalid("invalid USB control result"))
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
