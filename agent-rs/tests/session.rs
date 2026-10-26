//! Session component (session-component.md): the notice board the service writes and what the
//! component in each user session shows from it.

use openems_agent::session::{
    MAX_NOTICES, Notice, STARTUP_WINDOW_SECONDS, SessionBoard, SessionState, load, notices_to_show, path_for, tooltip,
};
use std::path::PathBuf;

fn at(when: &str) -> jiff::Timestamp {
    when.parse().unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("openems-session-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    path_for(&directory.join("state.json"))
}

fn notice(id: u64, when: &str) -> Notice {
    Notice { id, at: when.into(), kind: "app_closed".into(), text: format!("aviso {id}") }
}

#[test]
fn the_board_sits_next_to_the_state_file() {
    assert_eq!(
        path_for(&std::env::temp_dir().join("openems").join("state.json")),
        std::env::temp_dir().join("openems").join("session.json")
    );
}

#[test]
fn closed_apps_become_numbered_notices_in_portuguese_and_the_board_keeps_the_latest() {
    let path = scratch("board");
    let board = SessionBoard::open(&path);
    board.app_closed("PING.EXE", at("2026-10-25T12:00:00Z"));
    board.publish().unwrap();
    let state = load(&path).unwrap().unwrap();
    assert_eq!(state.notices.len(), 1);
    let first = &state.notices[0];
    assert_eq!((first.id, first.kind.as_str(), first.at.as_str()), (1, "app_closed", "2026-10-25T12:00:00Z"));
    assert_eq!(first.text, "PING.EXE foi fechado pela política da empresa.");
    for index in 0..MAX_NOTICES + 5 {
        board.app_closed(&format!("app{index}.exe"), at("2026-10-25T12:01:00Z"));
    }
    board.publish().unwrap();
    let state = load(&path).unwrap().unwrap();
    assert_eq!(state.notices.len(), MAX_NOTICES);
    assert_eq!(state.notices.last().unwrap().id, MAX_NOTICES as u64 + 6);
}

#[test]
fn ids_continue_after_a_service_restart() {
    let path = scratch("restart");
    let board = SessionBoard::open(&path);
    board.app_closed("a.exe", at("2026-10-25T12:00:00Z"));
    board.app_closed("b.exe", at("2026-10-25T12:00:00Z"));
    board.publish().unwrap();
    let again = SessionBoard::open(&path);
    again.app_closed("c.exe", at("2026-10-25T12:05:00Z"));
    again.publish().unwrap();
    let ids: Vec<u64> = load(&path).unwrap().unwrap().notices.iter().map(|notice| notice.id).collect();
    assert_eq!(ids, vec![1, 2, 3]);
}

#[test]
fn the_file_is_written_only_when_something_changed() {
    let path = scratch("dirty");
    let board = SessionBoard::open(&path);
    board.set_protected(true);
    board.contact(at("2026-10-25T12:00:00Z"));
    board.publish().unwrap();
    std::fs::remove_file(&path).unwrap();
    board.set_protected(true);
    board.publish().unwrap();
    assert!(!path.exists(), "no change, no write");
    board.contact(at("2026-10-25T12:00:15Z"));
    board.publish().unwrap();
    let state = load(&path).unwrap().unwrap();
    assert!(state.protected);
    assert_eq!(state.last_contact.as_deref(), Some("2026-10-25T12:00:15Z"));
}

#[test]
fn a_fresh_component_shows_only_recent_notices_then_only_new_ones() {
    let state = SessionState {
        protected: true,
        last_contact: None,
        notices: vec![
            notice(1, "2026-10-25T11:00:00Z"),
            notice(2, "2026-10-25T11:59:30Z"),
            notice(3, "2026-10-25T12:00:00Z"),
        ],
    };
    let now = at("2026-10-25T12:00:10Z");
    let first: Vec<u64> = notices_to_show(&state, None, now).iter().map(|notice| notice.id).collect();
    assert_eq!(first, vec![2, 3], "older than {STARTUP_WINDOW_SECONDS} s at start is history, not news");
    assert!(notices_to_show(&state, Some(3), now).is_empty());
    let later: Vec<u64> = notices_to_show(&state, Some(1), now).iter().map(|notice| notice.id).collect();
    assert_eq!(later, vec![2, 3]);
}

#[test]
fn the_tooltip_tells_whether_protection_is_on_and_when_the_server_was_last_seen() {
    let now = at("2026-10-25T12:10:00Z");
    let mut state = SessionState { protected: false, last_contact: None, notices: vec![] };
    assert_eq!(tooltip(&state, now), "RSM Endpoint: aguardando a política da empresa");
    state.protected = true;
    state.last_contact = Some("2026-10-25T12:09:30Z".into());
    assert_eq!(tooltip(&state, now), "RSM Endpoint: proteção ativa");
    state.last_contact = Some("2026-10-25T11:00:00Z".into());
    let offline = tooltip(&state, now);
    assert!(offline.starts_with("RSM Endpoint: proteção ativa, sem contato com o servidor desde "), "{offline}");
    state.last_contact = None;
    assert_eq!(tooltip(&state, now), "RSM Endpoint: proteção ativa, sem contato com o servidor");
}

#[test]
fn a_damaged_board_is_treated_as_empty_by_the_component() {
    let path = scratch("damaged");
    std::fs::write(&path, b"{not json").unwrap();
    assert!(load(&path).unwrap().is_none());
    let board = SessionBoard::open(&path);
    board.app_closed("x.exe", at("2026-10-25T12:00:00Z"));
    board.publish().unwrap();
    assert_eq!(load(&path).unwrap().unwrap().notices[0].id, 1);
}
