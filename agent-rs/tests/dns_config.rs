use openems_agent::config::AgentConfig;
use openems_agent::policy::{policy_digest, validate_assignment};
use openems_agent::runtime::{Logger, enforce};
use serde_json::json;
use std::sync::Arc;

#[test]
fn dns_filter_is_opt_in_and_requires_enforcement_and_a_valid_port() {
    let mut config = AgentConfig::new("http://127.0.0.1:8000", "test");
    assert!(!config.dns_filter);
    assert_eq!(config.dns_port, 53);
    config.dns_filter = true;
    assert!(config.validate().is_ok());
    config.dry_run = true;
    assert!(config.validate().is_err());
    config.dry_run = false;
    config.dns_port = 0;
    assert!(config.validate().is_err());
}

#[test]
fn dns_configuration_roundtrips_and_legacy_files_default_off() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("agent.json");
    let mut config = AgentConfig::new("http://127.0.0.1:8000", "test");
    config.dns_filter = true;
    config.dns_port = 15353;
    config.write_file(&path).unwrap();
    assert_eq!(AgentConfig::from_file(&path).unwrap(), config);
    std::fs::write(&path, r#"{"server": "http://127.0.0.1:8000", "devid": "test"}"#).unwrap();
    assert!(!AgentConfig::from_file(&path).unwrap().dns_filter);
    std::fs::write(&path, r#"{"server": "http://127.0.0.1:8000", "devid": "test", "dns_filter": "yes"}"#).unwrap();
    assert!(AgentConfig::from_file(&path).is_err());
    std::fs::write(&path, r#"{"server": "http://127.0.0.1:8000", "devid": "test", "dns_port": 70000}"#).unwrap();
    assert!(AgentConfig::from_file(&path).is_err());
}

#[test]
fn dns_mode_removes_the_managed_hosts_block_instead_of_writing_it() {
    let directory = tempfile::tempdir().unwrap();
    let hosts = directory.path().join("hosts");
    std::fs::write(
        &hosts,
        "# original\n# >>> openems managed block >>>\n0.0.0.0 old.example\n# <<< openems managed block <<<\n",
    )
    .unwrap();
    let mut config = AgentConfig::new("http://127.0.0.1:8000", "test");
    config.hosts_path = hosts.clone();
    config.dns_filter = true;
    let body = json!({"web_filter": {"blocked": ["*.example.com"]}});
    let digest = policy_digest(body.as_object().unwrap());
    let assignment =
        validate_assignment(&json!({"vdom": "Default", "version": 3, "digest": digest, "body": body})).unwrap();
    let log: Logger = Arc::new(|_: &str| {});
    let enforcement = enforce(&config, &assignment, &log).unwrap();
    assert_eq!(enforcement.sites, vec!["*.example.com".to_owned()]);
    assert_eq!(std::fs::read_to_string(&hosts).unwrap(), "# original\n");
}
