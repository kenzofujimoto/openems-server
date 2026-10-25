//! Removal authorization (tamper-protection.md, part 5b): uninstall.json and the decision every removal
//! command takes before changing anything.

use openems_agent::removal::{
    Allowed, Fetch, LOCKOUT_SECONDS, MAX_FAILURES, Refusal, authorize, load, mark_acked, path_for, store_secret,
    update_release,
};
use openems_agent::uninstall::{code, release_token};
use std::cell::Cell;
use std::path::PathBuf;

const NOW: i64 = 1_800_000_000;
const SECRET: [u8; 32] = [7; 32];

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("openems-removal-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    path_for(&directory.join("state.json"))
}

fn armed(name: &str) -> PathBuf {
    let path = scratch(name);
    store_secret(&path, "client-1", &SECRET).unwrap();
    mark_acked(&path).unwrap();
    path
}

fn unreachable(_: &str) -> Fetch {
    panic!("the server is not asked while a secret is stored")
}

#[test]
fn the_file_sits_next_to_the_state_file() {
    assert_eq!(
        path_for(&PathBuf::from(r"C:\ProgramData\openems\state.json")),
        PathBuf::from(r"C:\ProgramData\openems\uninstall.json")
    );
}

#[test]
fn a_valid_code_is_accepted_once_and_moves_the_counter() {
    let path = armed("once");
    let first = code(&SECRET, 1);
    assert_eq!(authorize(&path, Some("client-1"), Some(&first), NOW, unreachable).unwrap(), Ok(Allowed::Code(1)));
    assert_eq!(load(&path).unwrap().unwrap().last_used, 1);
    assert!(matches!(
        authorize(&path, Some("client-1"), Some(&first), NOW, unreachable).unwrap(),
        Err(Refusal::Rejected { .. })
    ));
    let typed = code(&SECRET, 3).to_lowercase().replace('-', " ");
    assert_eq!(authorize(&path, Some("client-1"), Some(&typed), NOW, unreachable).unwrap(), Ok(Allowed::Code(3)));
}

#[test]
fn removal_without_a_code_names_the_client_id_for_the_offline_tool() {
    let path = armed("required");
    let refusal = authorize(&path, Some("client-1"), None, NOW, unreachable).unwrap().unwrap_err();
    assert_eq!(refusal, Refusal::CodeRequired);
    assert!(refusal.message("client-1").contains("client-1"));
}

#[test]
fn repeated_wrong_codes_lock_removal_for_an_hour() {
    let path = armed("lockout");
    for attempt in 1..MAX_FAILURES {
        let decision = authorize(&path, Some("client-1"), Some("00000-00000"), NOW, unreachable).unwrap();
        assert_eq!(decision, Err(Refusal::Rejected { locked_until: None }), "attempt {attempt}");
    }
    let decision = authorize(&path, Some("client-1"), Some("00000-00000"), NOW, unreachable).unwrap();
    assert_eq!(decision, Err(Refusal::Rejected { locked_until: Some(NOW + LOCKOUT_SECONDS) }));
    let right = code(&SECRET, 1);
    assert_eq!(
        authorize(&path, Some("client-1"), Some(&right), NOW + 10, unreachable).unwrap(),
        Err(Refusal::Locked { until: NOW + LOCKOUT_SECONDS })
    );
    let later = NOW + LOCKOUT_SECONDS + 1;
    assert_eq!(authorize(&path, Some("client-1"), Some(&right), later, unreachable).unwrap(), Ok(Allowed::Code(1)));
    assert_eq!(load(&path).unwrap().unwrap().failures, 0, "a success clears the count");
}

#[test]
fn a_release_from_the_server_allows_removal_only_when_bound_to_this_secret() {
    let path = armed("release");
    assert!(!update_release(&path, Some(&"ab".repeat(32))).unwrap(), "a forged token is ignored");
    assert_eq!(authorize(&path, Some("client-1"), None, NOW, unreachable).unwrap(), Err(Refusal::CodeRequired));
    assert!(update_release(&path, Some(&release_token(&SECRET))).unwrap());
    assert_eq!(authorize(&path, Some("client-1"), None, NOW, unreachable).unwrap(), Ok(Allowed::Released));
    assert!(update_release(&path, None).unwrap(), "a revoked release is dropped");
    assert_eq!(authorize(&path, Some("client-1"), None, NOW, unreachable).unwrap(), Err(Refusal::CodeRequired));
}

#[test]
fn without_a_stored_secret_the_server_decides() {
    let unregistered = scratch("unregistered");
    assert_eq!(authorize(&unregistered, None, None, NOW, unreachable).unwrap(), Ok(Allowed::WithoutSecret));

    let offline = scratch("offline");
    assert_eq!(
        authorize(&offline, Some("client-1"), None, NOW, |_| Fetch::Unavailable).unwrap(),
        Ok(Allowed::WithoutSecret)
    );

    let deleted = scratch("deleted");
    assert_eq!(
        authorize(&deleted, Some("client-1"), None, NOW, |_| Fetch::AlreadyDelivered).unwrap(),
        Err(Refusal::SecretRemoved)
    );

    let late = scratch("late");
    let asked = Cell::new(String::new());
    let fetch = |client: &str| {
        asked.set(client.to_owned());
        Fetch::Delivered(SECRET.to_vec())
    };
    assert_eq!(authorize(&late, Some("client-1"), None, NOW, fetch).unwrap(), Err(Refusal::CodeRequired));
    assert_eq!(asked.take(), "client-1");
    let stored = load(&late).unwrap().unwrap();
    assert_eq!((stored.client_id.as_str(), stored.secret.as_str()), ("client-1", hex::encode(SECRET).as_str()));
}

#[test]
fn a_secret_from_an_older_registration_is_replaced() {
    let path = armed("reregistered");
    let fresh = [9u8; 32];
    let decision = authorize(&path, Some("client-2"), Some(&code(&fresh, 1)), NOW, |client| {
        assert_eq!(client, "client-2");
        Fetch::Delivered(fresh.to_vec())
    });
    assert_eq!(decision.unwrap(), Ok(Allowed::Code(1)));
    assert_eq!(load(&path).unwrap().unwrap().client_id, "client-2");
}

#[test]
fn an_edited_client_id_with_no_server_answer_keeps_the_stored_secret() {
    // state.json is writable by administrators: changing its client_id must not unlock removal offline.
    let path = armed("edited");
    assert_eq!(
        authorize(&path, Some("forged"), None, NOW, |_| Fetch::Unavailable).unwrap(),
        Err(Refusal::CodeRequired)
    );
    let right = code(&SECRET, 1);
    assert_eq!(
        authorize(&path, Some("forged"), Some(&right), NOW, |_| Fetch::Unavailable).unwrap(),
        Ok(Allowed::Code(1))
    );
    assert_eq!(load(&path).unwrap().unwrap().client_id, "client-1");
}

#[test]
fn storing_a_new_secret_starts_over() {
    let path = armed("restart");
    authorize(&path, Some("client-1"), Some(&code(&SECRET, 5)), NOW, unreachable).unwrap().unwrap();
    store_secret(&path, "client-1", &[1; 32]).unwrap();
    let state = load(&path).unwrap().unwrap();
    assert_eq!((state.last_used, state.failures, state.acked, state.release), (0, 0, false, None));
}

#[test]
fn an_unreadable_file_refuses_removal_instead_of_passing() {
    let path = scratch("corrupt");
    std::fs::write(&path, b"{not json").unwrap();
    assert!(authorize(&path, Some("client-1"), None, NOW, |_| Fetch::Unavailable).is_err());
}

mod commands {
    use super::*;
    use openems_agent::config::AgentConfig;
    use openems_agent::removal::authorize_removal_with;
    use openems_agent::state::EndpointState;
    use openems_agent::tamper::TamperKind;

    fn config(name: &str, client_id: Option<&str>) -> AgentConfig {
        let path = scratch(name);
        let mut config = AgentConfig::new("https://ems.example.com", "PC1");
        config.state_path = path.with_file_name("state.json");
        if let Some(client_id) = client_id {
            EndpointState {
                server: config.server.clone(),
                devid: config.devid.clone(),
                client_id: Some(client_id.into()),
                device_token: Some("token".into()),
                profile: None,
            }
            .save(&config.state_path)
            .unwrap();
        }
        config
    }

    #[test]
    fn a_refusal_is_an_error_naming_the_client_id_and_a_rejection_is_reported() {
        let config = config("command-refusal", Some("client-1"));
        store_secret(&path_for(&config.state_path), "client-1", &SECRET).unwrap();
        let mut reported = Vec::new();
        let error = authorize_removal_with(&config, None, NOW, unreachable, &mut |kind| reported.push(kind)).unwrap_err();
        assert!(error.to_string().contains("client-1"), "{error}");
        assert!(reported.is_empty(), "asking for a code is not tampering");
        authorize_removal_with(&config, Some("00000-00000"), NOW, unreachable, &mut |kind| reported.push(kind))
            .unwrap_err();
        assert_eq!(reported, vec![TamperKind::UninstallCodeRejected]);
        let allowed =
            authorize_removal_with(&config, Some(&code(&SECRET, 1)), NOW, unreachable, &mut |kind| reported.push(kind));
        assert_eq!(allowed.unwrap(), Allowed::Code(1));
        assert_eq!(reported.len(), 1);
    }

    #[test]
    fn removal_without_a_secret_is_reported_and_the_server_is_asked_for_the_registered_id() {
        let config = config("command-without", Some("client-7"));
        let mut reported = Vec::new();
        let allowed = authorize_removal_with(
            &config,
            None,
            NOW,
            |client| {
                assert_eq!(client, "client-7");
                Fetch::Unavailable
            },
            &mut |kind| reported.push(kind),
        );
        assert_eq!(allowed.unwrap(), Allowed::WithoutSecret);
        assert_eq!(reported, vec![TamperKind::UninstallWithoutSecret]);
    }

    #[test]
    fn a_damaged_state_file_does_not_bypass_a_stored_secret() {
        let config = config("command-damaged", None);
        store_secret(&path_for(&config.state_path), "client-1", &SECRET).unwrap();
        std::fs::write(&config.state_path, b"garbage").unwrap();
        let error = authorize_removal_with(&config, None, NOW, unreachable, &mut |_| {}).unwrap_err();
        assert!(error.to_string().contains("client-1"), "{error}");
    }
}
