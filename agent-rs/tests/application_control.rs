use openems_agent::applications::{Application, validate, resolve_rules};
use serde_json::json;

fn application() -> Application {
    Application { name:"Tool".into(), path:"C:\\Program Files\\Tools\\tool.exe".into(), sha256:"ab".repeat(32),
        publisher:"CN=Example Software, O=Example Software".into(), signature_valid:true,
        original_name:"tool.exe".into(), ..Default::default() }
}

#[test]
fn execution_and_network_rules_are_independent_and_normalized() {
    let policy = validate(Some(&json!({"blocked":["OLD.EXE"], "execution_rules":[
        {"id":"hash", "kind":"hash", "value":"AB".repeat(32), "sample_path":"C:\\Program Files\\Tools\\tool.exe"}
    ], "network_blocked":["C:\\Program Files\\Tools\\tool.exe"]}))).unwrap();
    assert_eq!(policy.execution_rules[0].value, "ab".repeat(32));
    assert_eq!(resolve_rules(&policy, &[application()]).unwrap()[0].sample_path.as_deref(), Some(application().path.as_str()));
    assert_eq!(policy.network_blocked.len(), 1);
}

#[test]
fn hash_and_publisher_rules_require_a_verified_local_sample() {
    let hash = validate(Some(&json!({"execution_rules":[{"id":"h","kind":"hash","value":"00".repeat(32)}]}))).unwrap();
    assert!(resolve_rules(&hash, &[application()]).is_err());
    let publisher = validate(Some(&json!({"execution_rules":[{"id":"p","kind":"publisher","value":application().publisher}]}))).unwrap();
    assert!(resolve_rules(&publisher, &[application()]).is_ok());
    let mut unsigned = application(); unsigned.signature_valid = false;
    assert!(resolve_rules(&publisher, &[unsigned]).is_err());
}

#[test]
fn name_uses_original_file_metadata_and_path_does_not_need_a_sample() {
    let policy = validate(Some(&json!({"execution_rules":[
        {"id":"n","kind":"name","value":"TOOL.EXE"},
        {"id":"p","kind":"path","value":"C:\\Tools\\new.exe"}
    ]}))).unwrap();
    let mut moved = application(); moved.path = "C:\\Tools\\renamed.exe".into();
    assert!(resolve_rules(&policy, &[moved]).is_ok());
    let mut wrong = application(); wrong.original_name = "different.exe".into();
    assert!(resolve_rules(&policy, &[wrong]).is_err());
}

#[test]
fn unsafe_targets_and_unknown_fields_are_refused() {
    for value in [
        json!({"network_blocked":["relative.exe"]}),
        json!({"network_blocked":["C:\\Tools\\*.exe"]}),
        json!({"execution_rules":[{"id":"bad","kind":"hash","value":"00"}]}),
        json!({"execution_rules":[{"id":"bad","kind":"publisher","value":"CN=Microsoft Corporation"}]}),
        json!({"execution_rules":[{"id":"bad","kind":"name","value":"svchost.exe"}]}),
        json!({"execution_rules":[{"id":"bad","kind":"path","value":"C:\\Windows\\System32\\services.exe"}]}),
        json!({"execution_rules":[{"id":"dup","kind":"path","value":"C:\\a.exe"},{"id":"dup","kind":"path","value":"C:\\b.exe"}]}),
    ] { assert!(validate(Some(&value)).is_err(), "{value}"); }
    assert!(validate(None).unwrap().execution_rules.is_empty());
}
