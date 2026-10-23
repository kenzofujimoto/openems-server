//! NRPT scripts are generated from fixed text and loopback addresses only; nothing is executed here.
use openems_agent::nrpt::{RULE_COMMENT, encode_command, install_script, remove_script};
use std::net::IpAddr;

fn loopbacks() -> Vec<IpAddr> {
    vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()]
}

#[test]
fn install_replaces_only_managed_leftovers_then_routes_root_namespace_to_loopback() {
    let script = install_script(&loopbacks()).unwrap();
    let removal = script.find("Remove-DnsClientNrptRule").unwrap();
    let addition = script.find("Add-DnsClientNrptRule").unwrap();
    assert!(removal < addition, "leftovers are removed before the new rule");
    assert!(script.contains("-Namespace '.'"));
    assert!(script.contains("-NameServers @('127.0.0.1','::1')"));
    assert!(script.contains(&format!("-Comment '{RULE_COMMENT}'")));
    assert!(script.contains("Clear-DnsClientCache"));
    assert!(script.starts_with("$ErrorActionPreference = 'Stop'"));
}

#[test]
fn removal_matches_comment_root_namespace_and_loopback_servers_exactly() {
    let script = remove_script();
    assert!(script.contains(&format!("$_.Comment -eq '{RULE_COMMENT}'")));
    assert!(script.contains("@($_.Namespace) -contains '.'"));
    assert!(script.contains("-notin @('127.0.0.1','::1')"));
    assert!(!script.contains("Add-DnsClientNrptRule"));
}

#[test]
fn only_loopback_servers_can_be_installed() {
    assert!(install_script(&[]).is_err());
    assert!(install_script(&["192.168.1.1".parse().unwrap()]).is_err());
    assert!(install_script(&["127.0.0.1".parse().unwrap(), "8.8.8.8".parse().unwrap()]).is_err());
    assert!(install_script(&["127.0.0.1".parse().unwrap()]).unwrap().contains("@('127.0.0.1')"));
}

#[test]
fn scripts_are_passed_as_utf16_base64() {
    // Known vector: "dir" in UTF-16LE base64, as accepted by powershell -EncodedCommand.
    assert_eq!(encode_command("dir"), "ZABpAHIA");
    assert_eq!(encode_command("ab'c"), "YQBiACcAYwA=");
}

/// Parses (never runs) both scripts with the PowerShell language parser.
#[cfg(windows)]
#[test]
fn scripts_parse_as_powershell() {
    for script in [install_script(&loopbacks()).unwrap(), remove_script()] {
        let check = format!(
            "$e=$null; [System.Management.Automation.Language.Parser]::ParseInput([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{}')),[ref]$null,[ref]$e) | Out-Null; if ($e.Count) {{ $e | Out-String | Write-Error; exit 1 }}",
            encode_command(&script)
        );
        let output = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &check])
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    }
}
