use openems_agent::linux_support::{ManagedFiles, observations_from_json, policy_plan, resolv_conf_servers};
use serde_json::json;
use std::net::IpAddr;

#[test]
fn linux_observations_require_live_adapters_and_default_gateway_neighbors() {
    let addresses = json!([
        {"ifname":"eth0", "flags":["UP","LOWER_UP"], "addr_info":[{"local":"192.168.1.20","prefixlen":24},{"local":"2001:db8::5","prefixlen":64}]},
        {"ifname":"lo", "flags":["UP"], "addr_info":[{"local":"127.0.0.1","prefixlen":8}]},
        {"ifname":"down0", "flags":[], "addr_info":[{"local":"10.0.0.1","prefixlen":8}]}
    ]);
    let routes = json!([{"dst":"default","dev":"eth0","gateway":"192.168.1.1"}]);
    let neighbors = json!([
        {"dev":"eth0","dst":"192.168.1.1","lladdr":"00:11:22:33:44:55","state":["STALE"]},
        {"dev":"eth0","dst":"192.168.1.2","lladdr":"aa:bb:cc:dd:ee:ff","state":["REACHABLE"]}
    ]);
    let observed = observations_from_json(&addresses, &routes, &neighbors, "search corp.example home.\n").unwrap();
    assert_eq!(observed.addresses.len(), 2);
    assert_eq!(observed.gateway_macs, ["001122334455"]);
    assert_eq!(observed.dns_suffixes, ["corp.example", "home"]);
    assert!(observed.public_ip.is_none());
    assert!(observations_from_json(&json!({}), &routes, &neighbors, "").is_err());
}

#[test]
fn upstreams_never_forward_back_into_the_local_resolver() {
    let servers = resolv_conf_servers("nameserver 127.0.0.53\nnameserver ::1\nnameserver 10.0.0.53 # LAN\nnameserver 2001:db8::53\nnameserver 10.0.0.53\nnameserver garbage\n");
    assert_eq!(servers, vec!["10.0.0.53".parse::<IpAddr>().unwrap(), "2001:db8::53".parse().unwrap()]);
}

#[test]
fn storage_rules_exempt_hid_and_translate_only_supported_linux_actions() {
    let plan = policy_plan(&json!({"usb_control":{"default_action":"block", "rules":[
        {"id":"trusted", "action":"allow", "vid":"0781", "pid":"5581", "serial":"TEST123"}
    ]}})).unwrap();
    let rules = plan.usbguard.unwrap();
    assert!(rules.starts_with("# Managed by openems\nallow with-interface one-of { 03:*:* 09:*:* }\n"));
    assert!(rules.contains("allow id 0781:5581 serial \"TEST123\" with-interface equals { 08:*:* }"));
    assert!(rules.ends_with("block with-interface equals { 08:*:* }\n"));
    assert!(policy_plan(&json!({"usb_control":{"default_action":"read_only","rules":[]}})).is_err());
    assert!(policy_plan(&json!({"usb_control":{"rules":[{"id":"x","action":"block","instance_id":"USBSTOR\\X"}]}})).is_err());
}

#[test]
fn fapolicyd_denies_paths_and_hashes_but_refuses_unsupported_identity_and_network_rules() {
    let hash = "ab".repeat(32);
    let plan = policy_plan(&json!({"app_control":{"execution_rules":[
        {"id":"hash", "kind":"hash", "value":hash},
        {"id":"path", "kind":"path", "value":"/opt/vendor/tool"}
    ]}})).unwrap();
    assert_eq!(plan.fapolicyd.unwrap(), format!("# Managed by openems\ndeny_audit perm=execute all : sha256hash={hash}\ndeny_audit perm=execute all : path=/opt/vendor/tool\n"));
    assert!(policy_plan(&json!({"app_control":{"execution_rules":[{"id":"publisher","kind":"publisher","value":"ACME"}]}})).is_err());
    assert!(policy_plan(&json!({"app_control":{"network_blocked":["/opt/vendor/tool"]}})).is_err());
    assert!(policy_plan(&json!({"app_control":{"execution_rules":[{"id":"path","kind":"path","value":"/opt/tool\nallow all"}]}})).is_err());
}

#[test]
fn owned_file_transaction_is_idempotent_and_cleanup_preserves_concurrent_changes() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("managed.conf");
    let unrelated = directory.path().join("other.conf");
    std::fs::write(&unrelated, "keep").unwrap();
    let journal = directory.path().join("journal.json");
    let transaction = ManagedFiles::new(journal.clone(), vec![target.clone()]);
    transaction.replace(&[(target.clone(), b"first".to_vec())]).unwrap();
    transaction.replace(&[(target.clone(), b"second".to_vec())]).unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"second");
    std::fs::write(&target, "operator change").unwrap();
    assert!(transaction.remove().is_err());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "operator change");
    assert!(journal.exists());
    std::fs::write(&target, "second").unwrap();
    transaction.remove().unwrap();
    assert!(!target.exists() && !journal.exists());
    assert_eq!(std::fs::read_to_string(unrelated).unwrap(), "keep");
}

#[test]
fn file_transactions_refuse_foreign_files_and_journal_paths() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("managed.conf");
    let journal = directory.path().join("journal.json");
    let transaction = ManagedFiles::new(journal.clone(), vec![target.clone()]);
    std::fs::write(&target, "foreign").unwrap();
    assert!(transaction.replace(&[(target.clone(), b"replacement".to_vec())]).is_err());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "foreign");
    let other = directory.path().join("unowned");
    assert!(transaction.replace(&[(other, b"bad".to_vec())]).is_err());
    assert!(!journal.exists());
}

#[test]
fn legacy_process_rules_without_owned_linux_configuration_are_a_noop() {
    let directory = tempfile::tempdir().unwrap();
    assert!(openems_agent::linux_support::apply_policy(&json!({"app_control":{"blocked":["test-process"]}}), &directory.path().join("state.json")).unwrap().is_empty());
    assert!(directory.path().read_dir().unwrap().next().is_none());
}
