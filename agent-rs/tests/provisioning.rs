use openems_agent::config::AgentConfig;
use openems_agent::provisioning::configure_install;

#[test]
fn fresh_install_requires_bootstrap_and_does_not_create_authority() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.json");
    assert!(configure_install(&path, None, false, false, false).is_err());
    assert!(!path.exists());
    let mut config = AgentConfig::new("https://ems.example.com", "NEW");
    config.authority_path = dir.path().join("https/authority.json");
    let installed = configure_install(&path, Some(config), false, true, false).unwrap();
    assert!(installed.block_page && installed.block_page_https);
    assert!(!installed.authority_path.exists());
    assert_eq!(AgentConfig::from_file(&path).unwrap(), installed);
}

#[test]
fn upgrade_preserves_custom_configuration_credentials_and_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.json");
    let state_path = dir.path().join("custom-state.json");
    std::fs::write(&state_path, "policy-and-token-state").unwrap();
    let original = serde_json::json!({
        "server":"https://ems.example.com", "devid":"REGISTERED", "vdom":"Custom",
        "hosts_path":dir.path().join("hosts"), "state_path":state_path,
        "authority_path":dir.path().join("private/authority.json"),
        "interval":91, "block_page":true, "block_page_https":false,
        "block_page_port":8080, "block_page_https_port":8443,
        "dry_run":true, "allow_insecure_http":true,
        "invitation":"original-invitation", "device_token":"existing-token"
    });
    std::fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
    let existing = AgentConfig::from_file(&path).unwrap();
    let bootstrap = AgentConfig::new("https://ems.example.com/", "REPLACEMENT");
    let installed = configure_install(&path, Some(bootstrap), false, false, false).unwrap();
    assert_eq!(installed, existing);
    assert_eq!(AgentConfig::from_file(&path).unwrap(), existing);
    assert_eq!(std::fs::read_to_string(state_path).unwrap(), "policy-and-token-state");
}

#[test]
fn corrupted_configuration_is_never_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.json");
    for bytes in [b"not JSON".as_slice(), br#"{"server":"https://ems.example.com","devid":"PC","unexpected":true}"#] {
        std::fs::write(&path, bytes).unwrap();
        assert!(
            configure_install(&path, Some(AgentConfig::new("https://ems.example.com", "NEW")), true, true, false).is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn different_server_and_invalid_options_preserve_original_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.json");
    let mut original = AgentConfig::new("https://ems.example.com", "REGISTERED");
    original.dry_run = true;
    original.write_file(&path).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert!(
        configure_install(&path, Some(AgentConfig::new("https://other.example.com", "NEW")), false, false, false).is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    // A dry-run installation cannot enable HTTPS enforcement.
    std::fs::write(&path, br#"{"server":"https://ems.example.com","devid":"PC","dry_run":true}"#).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert!(configure_install(&path, None, false, true, false).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[test]
fn false_flags_preserve_enabled_https_and_fresh_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.json");
    let initial =
        configure_install(&path, Some(AgentConfig::new("https://ems.example.com", "PC")), false, false, false).unwrap();
    assert!(!initial.block_page && !initial.block_page_https);
    let enabled = configure_install(&path, None, false, true, false).unwrap();
    assert!(enabled.block_page && enabled.block_page_https);
    assert_eq!(configure_install(&path, None, false, false, false).unwrap(), enabled);
}

#[test]
fn enabling_https_preserves_legacy_token_and_explicit_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.json");
    let original = serde_json::json!({
        "server":"https://ems.example.com", "devid":"REGISTERED", "dry_run":false,
        "device_token":"legacy-token", "invitation":"invite", "interval":31
    });
    std::fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
    configure_install(&path, None, false, true, false).unwrap();
    let actual: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut expected = original;
    expected["block_page"] = true.into();
    expected["block_page_https"] = true.into();
    assert_eq!(actual, expected);
}

#[test]
fn dns_option_is_opt_in_and_keeps_registered_settings() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.json");
    let original = serde_json::json!({
        "server":"https://ems.example.com", "devid":"REGISTERED", "vdom":"Custom",
        "state_path":dir.path().join("state.json"), "interval":42, "block_page":true
    });
    std::fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
    let existing = AgentConfig::from_file(&path).unwrap();
    assert_eq!(configure_install(&path, None, false, false, false).unwrap(), existing);
    let enabled = configure_install(&path, None, false, false, true).unwrap();
    assert_eq!(enabled, AgentConfig { dns_filter: true, ..existing.clone() });
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(saved["devid"], "REGISTERED");
    assert_eq!(saved["interval"], 42);
    assert_eq!(saved["dns_filter"], true);
    // Omitting the option later never turns DNS filtering off.
    assert_eq!(configure_install(&path, None, false, false, false).unwrap(), enabled);
}
