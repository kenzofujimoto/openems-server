use openems_agent::usb::{Action, Device, decide, merge_history, validate};
use serde_json::json;

fn storage() -> Device {
    Device {
        instance_id: "USBSTOR\\DISK&VEN_TEST\\SERIAL&0".into(),
        vid: "0781".into(),
        pid: "5581".into(),
        serial: "SERIAL".into(),
        class: "storage".into(),
        present: true,
        disk_number: Some(7),
        disk_unique_id: "USB-DISK-7".into(),
        ..Default::default()
    }
}

#[test]
fn rules_are_ordered_and_all_selectors_must_match() {
    let policy = validate(Some(&json!({"default_action":"block", "rules":[
        {"id":"approved", "action":"allow", "vid":"0781", "pid":"5581", "serial":"SERIAL"},
        {"id":"vendor", "action":"read_only", "vid":"0781"}
    ]})))
    .unwrap();
    assert_eq!(decide(&policy, &storage()), Action::Allow);
    let mut another = storage();
    another.serial = "ANOTHER".into();
    assert_eq!(decide(&policy, &another), Action::ReadOnly);
    another.vid = "1234".into();
    assert_eq!(decide(&policy, &another), Action::Block);
}

#[test]
fn storage_rules_never_apply_to_input_devices_or_system_disks() {
    let policy = validate(Some(&json!({"default_action":"block"}))).unwrap();
    for class in ["keyboard", "mouse", "hid", "other"] {
        let mut device = storage();
        device.class = class.into();
        assert_eq!(decide(&policy, &device), Action::Allow);
    }
    let mut boot = storage();
    boot.is_boot = true;
    assert_eq!(decide(&policy, &boot), Action::Allow);
    boot.is_boot = false;
    boot.is_system = true;
    assert_eq!(decide(&policy, &boot), Action::Allow);
}

#[test]
fn malformed_usb_rules_are_rejected_before_any_windows_command() {
    for value in [
        json!({"default_action":"deny"}),
        json!({"rules":[{"id":"empty","action":"block"}]}),
        json!({"rules":[{"id":"hid","action":"block","class":"keyboard"}]}),
        json!({"rules":[{"id":"bad","action":"block","vid":"../x"}]}),
        json!({"rules":[{"id":"dup","action":"block","class":"storage"},{"id":"dup","action":"allow","class":"storage"}]}),
        json!({"surprise":true}),
    ] {
        assert!(validate(Some(&value)).is_err(), "{value}");
    }
    let normalized = validate(Some(&json!({"rules":[{"id":"x","action":"block","vid":"ABCD"}]}))).unwrap();
    assert_eq!(normalized.rules[0].vid.as_deref(), Some("abcd"));
    assert_eq!(validate(None).unwrap().default_action, Action::Allow);
}

#[test]
fn history_preserves_first_seen_and_marks_disconnected_devices() {
    let mut previous = storage();
    previous.first_seen = "old".into();
    previous.last_seen = "old".into();
    let mut connected = storage();
    connected.product = "Updated label".into();
    let history = merge_history(&[previous], vec![connected], "now");
    assert_eq!(history[0].first_seen, "old");
    assert_eq!(history[0].last_seen, "now");
    let gone = merge_history(&history, vec![], "later");
    assert!(!gone[0].present);
    assert_eq!(gone[0].last_seen, "now");
    let wire = serde_json::to_value(&history[0]).unwrap();
    assert!(wire.get("disk_number").is_none());
    assert!(wire.get("disk_unique_id").is_none());
}
