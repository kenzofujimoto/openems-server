//! Session component channel (session-component.md). The service keeps a small board of protection status
//! and notices for users in session.json; openems-session.exe, running in each user session, reads it and
//! shows a tray icon and balloons. Only application names (and later USB products) appear: no personal data.

use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const MAX_NOTICES: usize = 20;
/// A component that starts (logon, restart) shows only notices this recent; older ones are history.
pub const STARTUP_WINDOW_SECONDS: i64 = 60;
/// Without a successful synchronization for this long, the tooltip says the server is out of reach.
const CONTACT_GRACE_SECONDS: i64 = 300;
/// SYSTEM writes; Administrators and Users only read.
const BOARD_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FR;;;BA)(A;;FR;;;BU)";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    pub id: u64,
    pub at: String,
    pub kind: String,
    pub text: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionState {
    /// The last policy was enforced.
    pub protected: bool,
    pub last_contact: Option<String>,
    pub notices: Vec<Notice>,
}

pub fn path_for(state_path: &Path) -> PathBuf {
    state_path.with_file_name("session.json")
}

/// Missing or damaged board: None (the component waits for the next write). Other read errors surface.
pub fn load(path: &Path) -> Result<Option<SessionState>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// The service's side: records status and notices, written to disk only when something changed.
pub struct SessionBoard {
    path: PathBuf,
    state: Mutex<(SessionState, bool)>,
}

impl SessionBoard {
    /// Continue the numbering of an existing board so a restarted service never reuses an id.
    pub fn open(path: &Path) -> Self {
        let mut state = load(path).ok().flatten().unwrap_or_default();
        state.protected = false;
        SessionBoard { path: path.to_owned(), state: Mutex::new((state, true)) }
    }

    fn update(&self, change: impl FnOnce(&mut SessionState) -> bool) {
        let mut guard = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        if change(&mut guard.0) {
            guard.1 = true;
        }
    }

    pub fn set_protected(&self, protected: bool) {
        self.update(|state| std::mem::replace(&mut state.protected, protected) != protected);
    }

    pub fn contact(&self, at: jiff::Timestamp) {
        let at = Some(at.to_string());
        self.update(|state| std::mem::replace(&mut state.last_contact, at.clone()) != at);
    }

    pub fn notice(&self, kind: &str, text: String, at: jiff::Timestamp) {
        self.update(|state| {
            let id = state.notices.last().map_or(1, |notice| notice.id + 1);
            state.notices.push(Notice { id, at: at.to_string(), kind: kind.into(), text });
            let excess = state.notices.len().saturating_sub(MAX_NOTICES);
            state.notices.drain(..excess);
            true
        });
    }

    pub fn app_closed(&self, name: &str, at: jiff::Timestamp) {
        self.notice("app_closed", format!("{name} foi fechado pela política da empresa."), at);
    }

    pub fn publish(&self) -> Result<()> {
        let mut guard = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        if !guard.1 {
            return Ok(());
        }
        let data = serde_json::to_vec(&guard.0).map_err(|error| crate::error::AgentError::Local(error.to_string()))?;
        crate::fsutil::atomic_write_protected(&self.path, &data, |file| {
            crate::fsutil::secure_file_with(file, BOARD_SDDL)
        })?;
        guard.1 = false;
        Ok(())
    }
}

fn parse(at: &str) -> Option<jiff::Timestamp> {
    at.parse().ok()
}

/// What a component should show now: after `last_shown`, or at start only the last minute.
pub fn notices_to_show(state: &SessionState, last_shown: Option<u64>, now: jiff::Timestamp) -> Vec<Notice> {
    state
        .notices
        .iter()
        .filter(|notice| match last_shown {
            Some(last) => notice.id > last,
            None => parse(&notice.at).is_some_and(|at| now.as_second() - at.as_second() <= STARTUP_WINDOW_SECONDS),
        })
        .cloned()
        .collect()
}

pub fn tooltip(state: &SessionState, now: jiff::Timestamp) -> String {
    if !state.protected {
        return "RSM Endpoint: aguardando a política da empresa".into();
    }
    match state.last_contact.as_deref().and_then(parse) {
        Some(at) if now.as_second() - at.as_second() <= CONTACT_GRACE_SECONDS => "RSM Endpoint: proteção ativa".into(),
        Some(at) => {
            let local = at.to_zoned(jiff::tz::TimeZone::system()).strftime("%d/%m %H:%M").to_string();
            format!("RSM Endpoint: proteção ativa, sem contato com o servidor desde {local}")
        }
        None => "RSM Endpoint: proteção ativa, sem contato com o servidor".into(),
    }
}
