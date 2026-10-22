use openems_agent::config::AgentConfig;
use openems_agent::trust::remove;
#[test]
fn removal_without_an_authority_is_an_unprivileged_noop() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("agent.json");
    let config = AgentConfig::new("http://127.0.0.1:1", "test");
    let mut value = config.to_json();
    value["authority_path"] = directory.path().join("https/authority.json").to_string_lossy().into_owned().into();
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(remove(Some(&path)).is_ok());
    assert!(!directory.path().join("https").exists());
}
