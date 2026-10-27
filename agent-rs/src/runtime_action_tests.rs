fn action_assignment(settings: serde_json::Value) -> Assignment {
    let body = json!({"web_filter":settings});
    validate_assignment(&json!({"vdom":"Default","version":2,
            "digest":crate::policy::policy_digest(body.as_object().unwrap()),"body":body}))
    .unwrap()
}

#[test]
fn missing_allow_category_refuses_monitoring_and_preserves_active_policy() {
    let (_dir, mut runtime) = network_runtime();
    runtime.cfg.dns_filter = true;
    runtime.lock().outside = Some(action_assignment(json!({"monitor_all":true,"category_actions":{"games":"allow"}})));
    assert!(!runtime.enforce_observed(Default::default(), Instant::now()));
    assert!(runtime.blocked_domains.contains("example.org"));
    assert!(matches!(runtime.lock().pending.as_ref().unwrap().outcome, Outcome::Failed(_)));
    assert!(runtime.blocked_domains.block_log().take().to_json()["events"].as_array().unwrap().is_empty());
}

#[test]
fn cached_allow_category_allows_offline_monitoring_without_logging_exception() {
    let (_dir, mut runtime) = network_runtime();
    runtime.cfg.dns_filter = true;
    runtime
        .blocked_domains
        .categories()
        .insert("games", crate::categories::CategorySet::from_domains(&["safe.example".into()]));
    runtime.lock().outside = Some(action_assignment(json!({"monitor_all":true,"category_actions":{"games":"allow"}})));
    assert!(runtime.enforce_observed(Default::default(), Instant::now()));
    assert_eq!(runtime.blocked_domains.decision("safe.example").action, crate::policy::WebAction::Allow);
}

#[test]
fn rejected_identity_requires_capability_advertisement_again() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut request = Vec::new();
        let mut byte = [0; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        let headers = String::from_utf8(request).unwrap();
        let length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase().strip_prefix("content-length:").map(|n| n.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        stream.read_exact(&mut vec![0; length]).unwrap();
        stream.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").unwrap();
    });
    let (_dir, mut runtime) = network_runtime();
    runtime.api = ApiClient::new(&format!("http://{address}"));
    runtime.capabilities_sent.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(!runtime.synchronize(0.0));
    server.join().unwrap();
    assert!(runtime.lock().client_id.is_none());
    assert!(!runtime.capabilities_sent.load(std::sync::atomic::Ordering::Relaxed));
}

#[test]
fn offline_start_does_not_publish_monitoring_until_allow_data_is_loaded() {
    let (_dir, runtime) = network_runtime();
    let assignment = action_assignment(json!({"monitor_all":true,"category_actions":{"games":"allow"}}));
    runtime.lock().cached = Some(assignment.clone());
    runtime.lock().outside = Some(assignment);
    runtime.save(&runtime.lock()).unwrap();
    let mut cfg = runtime.cfg.clone();
    cfg.dns_filter = true;
    let restored = Runtime::new(cfg, Arc::new(|_| {}), Arc::new(StopSignal::default())).unwrap();
    assert!(!restored.blocked_domains.decision("safe.example").log);
    assert!(!restored.enforce_local());
}

#[test]
fn expanded_taxonomy_matches_reference_labels() {
    for (id, label) in [
        ("ai", "Inteligência artificial"),
        ("bank", "Bancos"),
        ("financial", "Serviços financeiros"),
        ("jobsearch", "Empregos"),
        ("webhosting", "Hospedagem web"),
        ("celebrity", "Celebridades"),
    ] {
        assert_eq!(crate::policy::category_label(id), Some(label));
        action_assignment(json!({"category_actions":{id:"monitor"}}));
    }
    assert_eq!(crate::policy::CATEGORY_IDS.len(), 27);
}

#[test]
fn failed_category_refresh_keeps_active_allow_exceptions() {
    let (_dir, mut runtime) = network_runtime();
    runtime.cfg.dns_filter = true;
    let active = action_assignment(json!({"monitor_all":true,"category_actions":{"games":"allow"}}));
    runtime.blocked_domains.replace(active.web_filter().unwrap());
    runtime
        .blocked_domains
        .categories()
        .insert("games", crate::categories::CategorySet::from_domains(&["safe.example".into()]));
    runtime.lock().outside = Some(action_assignment(json!({"monitor_all":true,"category_actions":{"bank":"allow"}})));
    runtime.sync_categories("test", None);
    assert!(!runtime.enforce_local());
    assert!(!runtime.blocked_domains.decision("safe.example").log);
    assert!(runtime.blocked_domains.categories().loaded().contains(&"games".into()));
}

#[test]
fn empty_allow_category_does_not_make_monitoring_safe_to_activate() {
    let (_dir, mut runtime) = network_runtime();
    runtime.cfg.dns_filter = true;
    runtime.blocked_domains.categories().insert("games", crate::categories::CategorySet::default());
    runtime.lock().outside = Some(action_assignment(json!({"monitor_all":true,"category_actions":{"games":"allow"}})));
    assert!(!runtime.enforce_local());
    assert!(runtime.blocked_domains.contains("example.org"));
}

#[test]
fn global_monitoring_requires_legacy_category_data_too() {
    let (_dir, mut runtime) = network_runtime();
    runtime.cfg.dns_filter = true;
    runtime.lock().outside = Some(action_assignment(json!({"monitor_all":true,"blocked_categories":["games"]})));
    assert!(!runtime.enforce_local());
    assert!(runtime.blocked_domains.contains("example.org"));
}

#[test]
fn successful_registration_removes_the_consumed_invitation_from_the_config_file() {
    // 2026-10-27 review: the MSI-installed agent.json kept the one-time invitation after enrollment.
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut request = Vec::new();
        let mut byte = [0; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        let headers = String::from_utf8(request).unwrap();
        let length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase().strip_prefix("content-length:").map(|n| n.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        stream.read_exact(&mut vec![0; length]).unwrap();
        let body = br#"{"client_id":"enrolled-client","device_token":"enrolled-token"}"#;
        let head = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        stream.write_all(head.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        assert!(headers.starts_with("POST /fct/api/public/v1/register/"));
    });
    let (dir, mut runtime) = network_runtime();
    let path = dir.path().join("agent.json");
    runtime.cfg.invitation = Some("one-time-invitation-value".into());
    runtime.cfg.write_file(&path).unwrap();
    let mut on_disk: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    on_disk["custom_operator_field"] = json!("kept");
    std::fs::write(&path, serde_json::to_vec(&on_disk).unwrap()).unwrap();
    runtime.cfg.config_path = Some(path.clone());
    runtime.api = ApiClient::new(&format!("http://{address}"));
    runtime.lock().client_id = None;
    let _ = runtime.synchronize(0.0);
    server.join().unwrap();
    assert_eq!(runtime.lock().client_id.as_deref(), Some("enrolled-client"));
    let saved = std::fs::read_to_string(&path).unwrap();
    assert!(!saved.contains("one-time-invitation-value"), "consumed invitation left in agent.json");
    let saved: serde_json::Value = serde_json::from_str(&saved).unwrap();
    assert_eq!(saved["custom_operator_field"], json!("kept"), "only the invitation may be removed");
    assert_eq!(saved["server"], json!(runtime.cfg.server));
    assert_eq!(AgentConfig::from_file(&path).unwrap().invitation, None);
}

#[test]
fn config_loaded_from_a_file_remembers_its_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.json");
    AgentConfig::new("https://ems.example", "pc").write_file(&path).unwrap();
    assert_eq!(AgentConfig::from_file(&path).unwrap().config_path.as_deref(), Some(path.as_path()));
}
