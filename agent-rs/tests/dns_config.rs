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

#[test]
fn dns_mode_reports_capability_tag() {
    let body = json!({"web_filter": {"blocked": ["*.example.com"]}});
    let digest = policy_digest(body.as_object().unwrap());
    let assignment =
        validate_assignment(&json!({"vdom": "Default", "version": 3, "digest": digest, "body": body})).unwrap();
    let enforcement = openems_agent::runtime::Enforcement { sites: vec!["*.example.com".into()], ..Default::default() };
    let mut config = AgentConfig::new("http://127.0.0.1:8000", "test");
    assert!(
        !openems_agent::runtime::host_tags(&config, &assignment, &enforcement).contains(&"web-filter:dns".to_owned())
    );
    config.dns_filter = true;
    assert!(
        openems_agent::runtime::host_tags(&config, &assignment, &enforcement).contains(&"web-filter:dns".to_owned())
    );
}

fn scheduled_assignment(version: i64) -> openems_agent::policy::Assignment {
    let body = json!({"web_filter": {
        "blocked": ["other.org"], "timezone": "UTC",
        "scheduled": [{"blocked": ["*.facebook.com"], "days": ["mon"], "from": "08:00", "to": "18:00"}]
    }});
    let digest = policy_digest(body.as_object().unwrap());
    validate_assignment(&json!({"vdom": "Default", "version": version, "digest": digest, "body": body})).unwrap()
}

#[test]
fn hosts_mode_follows_schedule_windows_at_the_given_instant() {
    let directory = tempfile::tempdir().unwrap();
    let hosts = directory.path().join("hosts");
    std::fs::write(&hosts, "# original\n").unwrap();
    let mut config = AgentConfig::new("http://127.0.0.1:8000", "test");
    config.hosts_path = hosts.clone();
    let log: Logger = Arc::new(|_: &str| {});
    let assignment = scheduled_assignment(1);
    let monday_noon: jiff::Timestamp = "2026-10-26T12:00:00Z".parse().unwrap();
    let monday_night: jiff::Timestamp = "2026-10-26T19:00:00Z".parse().unwrap();
    openems_agent::runtime::enforce_at(&config, &assignment, &log, monday_noon).unwrap();
    assert!(std::fs::read_to_string(&hosts).unwrap().contains("0.0.0.0 www.facebook.com"));
    let enforcement = openems_agent::runtime::enforce_at(&config, &assignment, &log, monday_night).unwrap();
    let written = std::fs::read_to_string(&hosts).unwrap();
    assert!(!written.contains("facebook") && written.contains("0.0.0.0 other.org"));
    assert_eq!(enforcement.sites, vec!["other.org".to_owned()]);
}

#[test]
fn dns_cache_is_flushed_only_when_policy_or_open_windows_change() {
    use openems_agent::runtime::{dns_cache_flush_needed, dns_cache_state};
    let monday_noon: jiff::Timestamp = "2026-10-26T12:00:00Z".parse().unwrap();
    let later_noon: jiff::Timestamp = "2026-10-26T12:30:00Z".parse().unwrap();
    let monday_night: jiff::Timestamp = "2026-10-26T19:00:00Z".parse().unwrap();
    let first = dns_cache_state(&scheduled_assignment(1), monday_noon).unwrap();
    assert!(!dns_cache_flush_needed(None, &first), "the NRPT install already cleared the cache at start");
    assert!(!dns_cache_flush_needed(Some(&first), &dns_cache_state(&scheduled_assignment(1), later_noon).unwrap()));
    assert!(dns_cache_flush_needed(Some(&first), &dns_cache_state(&scheduled_assignment(1), monday_night).unwrap()));
    assert!(dns_cache_flush_needed(Some(&first), &dns_cache_state(&scheduled_assignment(2), monday_noon).unwrap()));
}

#[test]
fn agents_report_web_filter_v2_capability_and_keep_vdom_last() {
    let assignment = scheduled_assignment(1);
    let enforcement = openems_agent::runtime::Enforcement::default();
    let tags = openems_agent::runtime::host_tags(
        &AgentConfig::new("http://127.0.0.1:8000", "test"),
        &assignment,
        &enforcement,
    );
    assert!(tags.contains(&"web-filter:v2".to_owned()));
    assert_eq!(tags.last().unwrap(), "vdom:Default");
}

#[test]
fn anti_bypass_is_opt_in_requires_dns_filter_and_reports_a_tag() {
    let mut config = AgentConfig::new("http://127.0.0.1:8000", "test");
    assert!(!config.anti_bypass);
    config.anti_bypass = true;
    assert!(config.validate().is_err(), "anti-bypass needs the resolver");
    config.dns_filter = true;
    assert!(config.validate().is_ok());
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("agent.json");
    config.write_file(&path).unwrap();
    assert_eq!(AgentConfig::from_file(&path).unwrap(), config);
    let assignment = scheduled_assignment(1);
    let enforcement = openems_agent::runtime::Enforcement::default();
    let tags = openems_agent::runtime::host_tags(&config, &assignment, &enforcement);
    assert!(tags.contains(&"web-filter:anti-bypass".to_owned()));
    assert_eq!(tags.last().unwrap(), "vdom:Default");
}
