use openems_agent::applications::{Application, resolve_rules, validate};
use serde_json::json;

fn application() -> Application {
    Application {
        name: "Tool".into(),
        path: "C:\\Program Files\\Tools\\tool.exe".into(),
        sha256: "ab".repeat(32),
        publisher: "CN=Example Software, O=Example Software".into(),
        signature_valid: true,
        original_name: "tool.exe".into(),
        ..Default::default()
    }
}

#[test]
fn execution_and_network_rules_are_independent_and_normalized() {
    let policy = validate(Some(&json!({"blocked":["OLD.EXE"], "execution_rules":[
        {"id":"hash", "kind":"hash", "value":"AB".repeat(32), "sample_path":"C:\\Program Files\\Tools\\tool.exe"}
    ], "network_blocked":["C:\\Program Files\\Tools\\tool.exe"]})))
    .unwrap();
    assert_eq!(policy.execution_rules[0].value, "ab".repeat(32));
    assert_eq!(
        resolve_rules(&policy, &[application()]).unwrap()[0].sample_path.as_deref(),
        Some(application().path.as_str())
    );
    assert_eq!(policy.network_blocked.len(), 1);
}

#[test]
fn hash_and_publisher_rules_require_a_verified_local_sample() {
    let hash = validate(Some(&json!({"execution_rules":[{"id":"h","kind":"hash","value":"00".repeat(32)}]}))).unwrap();
    assert!(resolve_rules(&hash, &[application()]).is_err());
    let publisher =
        validate(Some(&json!({"execution_rules":[{"id":"p","kind":"publisher","value":application().publisher}]})))
            .unwrap();
    assert!(resolve_rules(&publisher, &[application()]).is_ok());
    let mut unsigned = application();
    unsigned.signature_valid = false;
    assert!(resolve_rules(&publisher, &[unsigned]).is_err());
}

#[test]
fn name_uses_original_file_metadata_and_path_does_not_need_a_sample() {
    let policy = validate(Some(&json!({"execution_rules":[
        {"id":"n","kind":"name","value":"TOOL.EXE"},
        {"id":"p","kind":"path","value":"C:\\Tools\\new.exe"}
    ]})))
    .unwrap();
    let mut moved = application();
    moved.path = "C:\\Tools\\renamed.exe".into();
    assert!(resolve_rules(&policy, &[moved]).is_ok());
    let mut wrong = application();
    wrong.original_name = "different.exe".into();
    assert!(resolve_rules(&policy, &[wrong]).is_err());
}

#[test]
fn unsafe_targets_and_unknown_fields_are_refused() {
    for value in [
        json!({"network_blocked":["relative.exe"]}),
        json!({"network_blocked":["C:\\Tools\\*.exe"]}),
        json!({"network_blocked":["//server/share/tool.exe"]}),
        json!({"network_blocked":["C:\\Tools\\.\\tool.exe"]}),
        json!({"execution_rules":[{"id":"_bad","kind":"hash","value":"ab".repeat(32)}]}),
        json!({"execution_rules":[{"id":"bad","kind":"hash","value":"00"}]}),
        json!({"execution_rules":[{"id":"bad","kind":"publisher","value":"CN=Microsoft Corporation"}]}),
        json!({"execution_rules":[{"id":"bad","kind":"name","value":"svchost.exe"}]}),
        json!({"execution_rules":[{"id":"bad","kind":"path","value":"C:\\Windows\\System32\\services.exe"}]}),
        json!({"execution_rules":[{"id":"dup","kind":"path","value":"C:\\a.exe"},{"id":"dup","kind":"path","value":"C:\\b.exe"}]}),
    ] {
        assert!(validate(Some(&value)).is_err(), "{value}");
    }
    assert!(validate(None).unwrap().execution_rules.is_empty());
}

#[test]
fn renaming_a_core_component_does_not_make_a_hash_deny_safe() {
    let mut renamed = application();
    renamed.path = "C:\\Tools\\renamed.exe".into();
    renamed.original_name = "services.exe".into();
    let policy =
        validate(Some(&json!({"execution_rules":[{"id":"core","kind":"hash","value":renamed.sha256}]}))).unwrap();
    assert!(resolve_rules(&policy, &[renamed]).is_err());
    assert!(validate(Some(&json!({"blocked":["services.exe"]}))).is_err());
}

#[cfg(windows)]
#[test]
fn windows_paths_cannot_use_ads_or_normalization_to_target_a_protected_component() {
    use std::io::Write;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    fn plan(path: &str) -> bool {
        let root = std::env::var_os("SystemRoot").unwrap();
        let mut process =
            Command::new(std::path::Path::new(&root).join("System32/WindowsPowerShell/v1.0/powershell.exe"))
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    include_str!("../../deploy/agent-applications.ps1"),
                ])
                .creation_flags(0x0800_0000)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
        process
            .stdin
            .take()
            .unwrap()
            .write_all(serde_json::to_string(&json!({"mode":"path-plan","paths":[path]})).unwrap().as_bytes())
            .unwrap();
        process.wait_with_output().unwrap().status.success()
    }

    assert!(plan("C:\\Tools\\allowed.exe"));
    for path in [
        "/Tools/allowed.exe",
        "C:\\Tools\\allowed.exe:stream",
        "C:\\Windows.\\System32\\test.exe",
        "C:\\Tools\\.\\allowed.exe",
    ] {
        assert!(!plan(path), "unsafe Windows path accepted: {path}");
    }
}

#[test]
fn present_only_rules_are_skipped_without_a_local_sample_while_strict_rules_still_fail() {
    let policy = validate(Some(&json!({"execution_rules":[
        {"id":"catalog-a", "kind":"publisher", "value":"CN=Absent Vendor", "if_present":true},
        {"id":"catalog-b", "kind":"publisher", "value":"CN=Example Software, O=Example Software", "if_present":true}
    ]})))
    .unwrap();
    let resolved = resolve_rules(&policy, &[application()]).unwrap();
    assert_eq!(resolved.iter().map(|rule| rule.id.as_str()).collect::<Vec<_>>(), ["catalog-b"]);
    let strict = validate(Some(&json!({"execution_rules":[{"id":"a", "kind":"publisher", "value":"CN=Absent Vendor"}]}))).unwrap();
    assert!(resolve_rules(&strict, &[application()]).is_err());
    assert!(validate(Some(&json!({"execution_rules":[{"id":"a", "kind":"publisher", "value":"CN=X", "if_present":"yes"}]}))).is_err());
}
