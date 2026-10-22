use openems_agent::config::AgentConfig;

#[test]
fn https_requires_enforcement_distinct_nonzero_ports() {
    let mut config = AgentConfig::new("http://127.0.0.1:8000", "test");
    config.block_page_https = true;
    assert!(config.validate().is_err());
    config.block_page = true;
    assert!(config.validate().is_ok());
    config.block_page_https_port = 0;
    assert!(config.validate().is_err());
    config.block_page_https_port = config.block_page_port;
    assert!(config.validate().is_err());
    config.block_page_https_port = 443;
    config.dry_run = true;
    assert!(config.validate().is_err());
}

#[test]
fn https_configuration_roundtrips_in_disposable_directory() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("agent.json");
    let mut config = AgentConfig::new("http://127.0.0.1:8000", "test");
    config.block_page = true;
    config.block_page_https = true;
    config.block_page_https_port = 14443;
    config.authority_path = directory.path().join("authority.json");
    config.write_file(&path).unwrap();
    let loaded = AgentConfig::from_file(&path).unwrap();
    assert_eq!(loaded, config);
}
