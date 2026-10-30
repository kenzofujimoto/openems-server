//! Bounded PowerShell adapter: scripts are compile-time constants; policy travels only as JSON stdin.

use crate::error::{AgentError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Event {
    pub kind: String,
    pub detail: String,
    #[serde(default = "default_rule_id")]
    pub rule_id: String,
}

fn default_rule_id() -> String {
    "policy".into()
}

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
#[cfg(windows)]
const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x0000_4000;

#[cfg(windows)]
pub fn run(script: &'static str, request: &Value) -> Result<Value> {
    run_with_flags(script, request, CREATE_NO_WINDOW)
}

/// Inventory collection: yields CPU so it never slows enforcement or the applications it inventories.
#[cfg(windows)]
pub fn run_background(script: &'static str, request: &Value) -> Result<Value> {
    run_with_flags(script, request, CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS)
}

#[cfg(windows)]
fn run_with_flags(script: &'static str, request: &Value, flags: u32) -> Result<Value> {
    use std::io::{Read, Write};
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const LIMIT: u64 = 4 * 1024 * 1024;
    let bytes = serde_json::to_vec(request).map_err(|_| AgentError::Local("invalid control request".into()))?;
    if bytes.len() as u64 > LIMIT {
        return Err(AgentError::Local("control request exceeds its size limit".into()));
    }
    let system_root =
        std::env::var_os("SystemRoot").ok_or_else(|| AgentError::Local("Windows directory unavailable".into()))?;
    let executable = std::path::Path::new(&system_root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let mut child = Command::new(executable)
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
        .creation_flags(flags)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or_else(|| AgentError::Local("control output unavailable".into()))?;
    let stderr = child.stderr.take().ok_or_else(|| AgentError::Local("control diagnostics unavailable".into()))?;
    let output = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take(LIMIT + 1).read_to_end(&mut bytes).map(|_| bytes)
    });
    let diagnostics = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.take(64 * 1024).read_to_end(&mut bytes).map(|_| bytes)
    });
    let write =
        child.stdin.take().ok_or_else(|| AgentError::Local("control input unavailable".into()))?.write_all(&bytes);
    if write.is_err() {
        let _ = child.kill();
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = output.join();
            let _ = diagnostics.join();
            return Err(AgentError::Local("Windows control timed out; its journal is retained for recovery".into()));
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let bytes = output.join().map_err(|_| AgentError::Local("control reader failed".into()))??;
    let _ = diagnostics.join();
    if !status.success() || write.is_err() || bytes.len() as u64 > LIMIT {
        let error = serde_json::from_slice::<Value>(&bytes).ok();
        let message = match error.as_ref().and_then(|value| value["error"].as_str()) {
            Some("restart_required") => "Windows control requires a restart; its protected journal is retained",
            Some("unsupported") => "Windows does not support the requested control",
            _ => "Windows control failed; verify OS support and its protected journal",
        };
        return Err(AgentError::Local(message.into()));
    }
    serde_json::from_slice(&bytes).map_err(|_| AgentError::Local("Windows control returned invalid output".into()))
}

#[cfg(not(windows))]
pub fn run(_script: &'static str, _request: &Value) -> Result<Value> {
    Err(AgentError::Local("this control adapter requires Windows".into()))
}

#[cfg(not(windows))]
pub fn run_background(script: &'static str, request: &Value) -> Result<Value> {
    run(script, request)
}

pub fn path(path: &std::path::Path) -> Result<&str> {
    path.to_str().ok_or_else(|| AgentError::Local("control state path is not valid Unicode".into()))
}

pub fn invalid(message: &str) -> AgentError {
    AgentError::Policy(message.into())
}

pub fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

pub fn text(value: &str, limit: usize) -> bool {
    !value.is_empty() && value == value.trim() && value.chars().count() <= limit && !value.chars().any(char::is_control)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use serde_json::json;

    const USB: &str = include_str!("../../deploy/agent-usb.ps1");
    const APPLICATIONS: &str = include_str!("../../deploy/agent-applications.ps1");

    #[test]
    fn background_inventory_gets_a_longer_limit_than_enforcement() {
        // A real notebook's application inventory exceeded the 120 s enforcement limit.
        assert_eq!(CONTROL_TIMEOUT, std::time::Duration::from_secs(120));
        assert!(INVENTORY_TIMEOUT >= std::time::Duration::from_secs(600));
        const SLOW: &str = "[Console]::In.ReadToEnd()|Out-Null; Start-Sleep -Seconds 5; '{}'";
        let error = run_with_limits(SLOW, &json!({}), CREATE_NO_WINDOW, std::time::Duration::from_millis(500)).unwrap_err();
        assert!(error.to_string().contains("timed out"));
    }

    #[test]
    fn background_collection_yields_cpu_to_enforcement() {
        const PRIORITY: &str = "[Console]::In.ReadToEnd()|Out-Null; @{priority=[string](Get-Process -Id $PID).PriorityClass}|ConvertTo-Json -Compress";
        assert_eq!(run(PRIORITY, &json!({})).unwrap()["priority"], "Normal");
        assert_eq!(run_background(PRIORITY, &json!({})).unwrap()["priority"], "BelowNormal");
    }

    #[test]
    fn inventories_run_as_background_collections() {
        for source in [include_str!("usb.rs"), include_str!("applications.rs")] {
            assert!(source.contains(r#"adapter::run_background(SCRIPT, &json!({"mode":"inventory"}))"#));
            assert!(!source.contains(r#"adapter::run(SCRIPT, &json!({"mode":"inventory"}))"#));
        }
    }

    #[test]
    fn embedded_scripts_parse_without_running_any_mutation() {
        const PARSER: &str = "$ErrorActionPreference='Stop'; $r=[Console]::In.ReadToEnd()|ConvertFrom-Json; $e=$null; [System.Management.Automation.PSParser]::Tokenize($r.source,[ref]$e)|Out-Null; @{errors=@($e|ForEach-Object Message)}|ConvertTo-Json -Compress";
        for script in [USB, APPLICATIONS] {
            assert_eq!(run(PARSER, &json!({"source":script})).unwrap()["errors"], json!([]));
        }
    }

    #[test]
    fn usb_inventory_reads_product_id_without_overwriting_powershell_pid() {
        let script = format!(
            "function Get-PnpDevice {{ [pscustomobject]@{{InstanceId='USB\\VID_0781&PID_5581\\sample';Class='HIDClass';FriendlyName='Fixture'}} }}\nfunction Get-CimInstance {{ @() }}\nfunction Get-PnpDeviceProperty {{ [pscustomobject]@{{Data='Fixture'}} }}\n{USB}"
        );
        let script: &'static str = Box::leak(script.into_boxed_str());
        let result = run(script, &json!({"mode":"inventory"})).unwrap();
        assert_eq!(result["inventory"][0]["pid"], "5581");
        assert_eq!(result["inventory"][0]["class"], "hid");
    }

    #[test]
    fn usb_inventory_skips_virtual_non_usb_disks_before_querying_storage_management() {
        let script = format!(
            r#"function Get-PnpDevice {{ [pscustomobject]@{{InstanceId='SCSI\DISK&VEN_MSFT\VIRTUAL';Class='DiskDrive';FriendlyName='Virtual disk'}} }}
function Get-CimInstance {{ [pscustomobject]@{{PNPDeviceID='SCSI\DISK&VEN_MSFT\VIRTUAL';Index=0;InterfaceType='SCSI'}} }}
function Get-PnpDeviceProperty {{ [pscustomobject]@{{Data=$null}} }}
function Get-Disk {{ throw 'Storage management is unavailable for the non-USB virtual disk' }}
{USB}"#
        );
        let script: &'static str = Box::leak(script.into_boxed_str());
        let result = run(script, &json!({"mode":"inventory"})).unwrap();
        assert_eq!(result["inventory"], json!([]));
    }

    #[test]
    fn usb_inventory_keeps_storage_identity_and_boot_protection_for_all_usb_evidence() {
        for (instance, ancestor, interface) in [
            (r"USBSTOR\DISK\sample", "", "SCSI"),
            (r"SCSI\DISK\sample", r"USB\VID_0781&PID_5581\sample", "SCSI"),
            (r"SCSI\DISK\sample", "", "USB"),
        ] {
            let script = format!(
                r#"function Get-PnpDevice {{ [pscustomobject]@{{InstanceId='{instance}';Class='DiskDrive';FriendlyName='USB storage'}} }}
function Get-CimInstance {{ [pscustomobject]@{{PNPDeviceID='{instance}';Index=2;InterfaceType='{interface}';SerialNumber='SERIAL';Manufacturer='Fixture';Model='Storage'}} }}
function Get-PnpDeviceProperty {{ param($InstanceId,$KeyName) [pscustomobject]@{{Data=$(if ($KeyName -eq 'DEVPKEY_Device_Parent' -and $InstanceId -eq '{instance}') {{ '{ancestor}' }} else {{ '' }})}} }}
function Get-Disk {{ [pscustomobject]@{{BusType='USB';Number=2;UniqueId='unique-fixture';IsBoot=$true;IsSystem=$true}} }}
function Get-Partition {{ @() }}
{USB}"#
            );
            let script: &'static str = Box::leak(script.into_boxed_str());
            let result = run(script, &json!({"mode":"inventory"})).unwrap();
            assert_eq!(result["inventory"][0]["class"], "storage");
            assert_eq!(result["inventory"][0]["disk_unique_id"], "unique-fixture");
            assert_eq!(result["inventory"][0]["is_boot"], true);
            assert_eq!(result["inventory"][0]["is_system"], true);
        }
    }

    #[test]
    fn usb_inventory_does_not_hide_real_usb_storage_query_failures() {
        let script = format!(
            r#"function Get-PnpDevice {{ [pscustomobject]@{{InstanceId='USBSTOR\DISK\sample';Class='DiskDrive';FriendlyName='USB storage'}} }}
function Get-CimInstance {{ [pscustomobject]@{{PNPDeviceID='USBSTOR\DISK\sample';Index=2;InterfaceType='USB'}} }}
function Get-PnpDeviceProperty {{ [pscustomobject]@{{Data=$null}} }}
function Get-Disk {{ throw 'Real USB storage identity cannot be verified' }}
{USB}"#
        );
        let script: &'static str = Box::leak(script.into_boxed_str());
        assert!(run(script, &json!({"mode":"inventory"})).is_err());
    }

    #[test]
    fn application_inventory_tolerates_empty_uninstall_registry_keys() {
        let script = format!(
            "function Get-CimInstance {{ @() }}\nfunction Test-Path {{ $true }}\nfunction Get-ChildItem {{ [pscustomobject]@{{PSPath='fixture';PSChildName='empty'}} }}\nfunction Get-ItemProperty {{ $null }}\n{APPLICATIONS}"
        );
        let script: &'static str = Box::leak(script.into_boxed_str());
        let result = run(script, &json!({"mode":"inventory"})).unwrap();
        assert_eq!(result["inventory"], json!([]));
    }

    #[test]
    fn usb_script_plan_preserves_hid_and_boot_storage() {
        let result = run(
            USB,
            &json!({"mode":"plan", "policy":{"default_action":"block","rules":[
                {"id":"approved","action":"allow","vid":"0781","serial":"SERIAL"}
            ]}, "inventory":[
                {"instance_id":"HID\\mouse","class":"mouse"},
                {"instance_id":"USBSTOR\\boot","class":"storage","is_boot":true},
                {"instance_id":"USBSTOR\\allowed","class":"storage","vid":"0781","serial":"SERIAL"},
                {"instance_id":"USBSTOR\\blocked","class":"storage","vid":"0781","serial":"OTHER"}
            ]}),
        )
        .unwrap();
        assert_eq!(result["changes"], json!([{"instance_id":"USBSTOR\\blocked","action":"block"}]));
    }

    #[test]
    fn code_integrity_events_need_enforcement_id_and_the_owned_policy_guid() {
        let guid = "{83D4D642-7C56-470C-AFA1-E6988DA8FE7C}";
        for (event_id, policy, expected) in
            [(3077, guid, true), (3076, guid, false), (3077, "{00000000-0000-0000-0000-000000000000}", false)]
        {
            let xml = format!(
                "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>{event_id}</EventID></System><EventData><Data Name=\"PolicyGUID\">{policy}</Data><Data Name=\"FileName\">C:\\Tools\\denied.exe</Data></EventData></Event>"
            );
            let result = run(APPLICATIONS, &json!({"mode":"event-plan","policy_id":guid,"xml":xml})).unwrap();
            assert_eq!(result["events"].as_array().unwrap().len(), usize::from(expected));
            if expected {
                assert_eq!(result["events"][0]["kind"], "app_block");
                assert_eq!(result["events"][0]["rule_id"], guid.trim_matches(['{', '}']));
            }
        }
        assert!(run(APPLICATIONS, &json!({"mode":"event-plan","policy_id":guid,"xml":"<!DOCTYPE x [<!ENTITY y SYSTEM 'file:///C:/private'>]><Event>&y;</Event>"})).is_err());
    }

    #[test]
    fn non_system_apply_refuses_before_creating_a_journal() {
        if crate::authority::require_system().is_ok() {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let journal = directory.path().join("must-not-exist.json");
        for script in [USB, APPLICATIONS] {
            assert!(run(script, &json!({"mode":"apply","state_path":journal,"policy":{}})).is_err());
            assert!(!journal.exists());
        }
    }
}
