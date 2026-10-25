//! Removal authorization (tamper-protection.md, part 5b). uninstall.json, next to the state file and
//! readable only by SYSTEM, keeps this registration's secret, the last code counter used, wrong
//! attempts and the server's release. Every removal command asks `authorize` before changing anything.

use crate::error::{AgentError, Result};
use crate::uninstall::{release_token, verify};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Wrong codes in a row before removal is locked.
pub const MAX_FAILURES: u32 = 5;
pub const LOCKOUT_SECONDS: i64 = 3600;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UninstallState {
    pub client_id: String,
    /// Hex of the 32-byte secret.
    pub secret: String,
    /// The server confirmed it will not hand this secret out again.
    pub acked: bool,
    pub last_used: u64,
    pub failures: u32,
    pub locked_until: Option<i64>,
    pub release: Option<String>,
}

impl UninstallState {
    fn secret_bytes(&self) -> Result<Vec<u8>> {
        hex::decode(&self.secret)
            .ok()
            .filter(|secret| secret.len() == 32)
            .ok_or_else(|| AgentError::Local("uninstall.json holds an invalid secret".into()))
    }
}

/// What the server answered when asked for the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetch {
    Delivered(Vec<u8>),
    /// The secret was delivered and confirmed before: this machine lost or deleted it.
    AlreadyDelivered,
    /// No answer, or the server has no uninstall codes configured.
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Allowed {
    Code(u64),
    Released,
    /// No secret was ever stored and the server could not provide one; reported as tampering.
    WithoutSecret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    CodeRequired,
    Rejected { locked_until: Option<i64> },
    Locked { until: i64 },
    SecretRemoved,
}

impl Refusal {
    pub fn message(&self, client_id: &str) -> String {
        match self {
            Refusal::CodeRequired => format!(
                "an uninstall code is required (UNINSTALLCODE for msiexec, --uninstall-code here); generate it in the \
                 panel or offline for client_id {client_id}"
            ),
            Refusal::Rejected { locked_until: None } => "the uninstall code was rejected".into(),
            Refusal::Rejected { locked_until: Some(until) } | Refusal::Locked { until } => format!(
                "too many wrong uninstall codes; removal is locked until {}",
                jiff::Timestamp::from_second(*until).map_or_else(|_| until.to_string(), |at| at.to_string())
            ),
            Refusal::SecretRemoved => format!(
                "this machine's uninstall secret was removed; ask an administrator to reopen its delivery or to \
                 release removal (client_id {client_id})"
            ),
        }
    }
}

pub type Decision = std::result::Result<Allowed, Refusal>;

pub fn path_for(state_path: &Path) -> PathBuf {
    state_path.with_file_name("uninstall.json")
}

/// Missing file: None. Any other failure (denied access, damaged JSON) is an error, never "no secret".
pub fn load(path: &Path) -> Result<Option<UninstallState>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| AgentError::Local("uninstall.json is damaged; ask an administrator to release removal".into()))
}

pub fn save(path: &Path, state: &UninstallState) -> Result<()> {
    let data = serde_json::to_vec(state).map_err(|error| AgentError::Local(format!("uninstall.json: {error}")))?;
    crate::fsutil::atomic_write_protected(path, &data, protect)
}

/// SYSTEM only when running as SYSTEM (the service and the installer); a developer run keeps it private.
fn protect(path: &Path) -> Result<()> {
    #[cfg(windows)]
    if crate::authority::require_system().is_ok() {
        return crate::authority::secure_authority_file(path);
    }
    crate::fsutil::secure_file(path)
}

/// A new secret for `client_id`: counter, attempts and release start over.
pub fn store_secret(path: &Path, client_id: &str, secret: &[u8]) -> Result<()> {
    save(path, &UninstallState { client_id: client_id.into(), secret: hex::encode(secret), ..Default::default() })
}

pub fn mark_acked(path: &Path) -> Result<()> {
    let mut state = load(path)?.ok_or_else(|| AgentError::Local("no uninstall secret to confirm".into()))?;
    state.acked = true;
    save(path, &state)
}

/// Keep the server's release only when it is bound to this secret; None drops a revoked one.
/// Returns whether the stored release changed.
pub fn update_release(path: &Path, offered: Option<&str>) -> Result<bool> {
    let Some(mut state) = load(path)? else {
        return Ok(false);
    };
    let expected = release_token(&state.secret_bytes()?);
    let release = offered.filter(|token| *token == expected).map(str::to_owned);
    if release == state.release {
        return Ok(false);
    }
    state.release = release;
    save(path, &state)?;
    Ok(true)
}

/// Decide whether removal may proceed. `client_id` is the current registration (state.json);
/// `fetch` asks the server for its secret when none is stored for it.
pub fn authorize(
    path: &Path,
    client_id: Option<&str>,
    typed: Option<&str>,
    now: i64,
    fetch: impl FnOnce(&str) -> Fetch,
) -> Result<Decision> {
    let stored = load(path)?;
    let current = stored.as_ref().is_some_and(|state| client_id.is_none_or(|id| id == state.client_id));
    let mut state = match (stored, client_id) {
        (Some(state), _) if current => state,
        // Never registered and nothing stored (a stored state was taken by the arm above).
        (_, None) => return Ok(Ok(Allowed::WithoutSecret)),
        (stored, Some(client_id)) => match fetch(client_id) {
            Fetch::Delivered(secret) => {
                store_secret(path, client_id, &secret)?;
                load(path)?.ok_or_else(|| AgentError::Local("uninstall.json was not written".into()))?
            }
            Fetch::AlreadyDelivered => return Ok(Err(Refusal::SecretRemoved)),
            // An older registration's secret still protects removal: state.json is writable by
            // administrators, so a changed client_id alone must not unlock it.
            Fetch::Unavailable => match stored {
                Some(state) => state,
                None => return Ok(Ok(Allowed::WithoutSecret)),
            },
        },
    };
    let secret = state.secret_bytes()?;
    if state.release.as_deref() == Some(release_token(&secret).as_str()) {
        return Ok(Ok(Allowed::Released));
    }
    if let Some(until) = state.locked_until.filter(|until| now < *until) {
        return Ok(Err(Refusal::Locked { until }));
    }
    let Some(typed) = typed.filter(|typed| !typed.trim().is_empty()) else {
        return Ok(Err(Refusal::CodeRequired));
    };
    match verify(&secret, typed, state.last_used) {
        Some(counter) => {
            state.last_used = counter;
            state.failures = 0;
            state.locked_until = None;
            save(path, &state)?;
            Ok(Ok(Allowed::Code(counter)))
        }
        None => {
            state.failures += 1;
            let locked_until = (state.failures >= MAX_FAILURES).then_some(now + LOCKOUT_SECONDS);
            if locked_until.is_some() {
                state.failures = 0;
                state.locked_until = locked_until;
            }
            // Persisted before answering: if the count cannot be saved, removal is refused anyway.
            save(path, &state)?;
            Ok(Err(Refusal::Rejected { locked_until }))
        }
    }
}
