//! Policy validation, a port of agent/policy.py checked against shared vectors.

use crate::canonical::canonical_json;
use crate::error::{AgentError, Result};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const MAX_ENTRIES: usize = 10_000;

pub fn policy_digest(body: &Map<String, Value>) -> String {
    let encoded = canonical_json(&Value::Object(body.clone()));
    hex::encode(Sha256::digest(encoded.as_bytes()))
}

fn invalid(message: &str) -> AgentError {
    AgentError::Policy(message.to_owned())
}

fn is_python_space(character: char) -> bool {
    // str.isspace() also treats the ASCII information separators as spaces.
    character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
}

fn valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    let alphanumeric = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    !bytes.is_empty()
        && bytes.len() <= 63
        && alphanumeric(&bytes[0])
        && alphanumeric(&bytes[bytes.len() - 1])
        && bytes.iter().all(|byte| alphanumeric(byte) || *byte == b'-')
}

pub fn normalize_domain(value: &str) -> Result<String> {
    if value.is_empty() || value.chars().any(is_python_space) {
        return Err(invalid("blocked domain must be a nonempty hostname without whitespace"));
    }
    if value.chars().any(|c| "*/\\:@?#%".contains(c)) || value.ends_with('.') {
        return Err(invalid("URLs, wildcards, addresses and paths are not supported domains"));
    }
    let domain = if value.is_ascii() {
        value.to_ascii_lowercase()
    } else {
        idna::domain_to_ascii(value).map_err(|_| invalid("invalid IDNA hostname"))?
    };
    let labels: Vec<&str> = domain.split('.').collect();
    if domain.len() > 253 || labels.len() < 2 || !labels.iter().all(|label| valid_label(label)) {
        return Err(invalid("invalid hostname"));
    }
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return Err(invalid("IP addresses are not supported domains"));
    }
    Ok(domain)
}

pub fn normalize_process(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let first_ok = bytes.first().is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_');
    let rest_ok = bytes.iter().skip(1).all(|byte| byte.is_ascii_alphanumeric() || b"_. -".contains(byte));
    if !first_ok || !rest_ok || bytes.len() > 254 {
        return Err(invalid("blocked application must be an exact executable image name"));
    }
    if value != value.trim() || value.contains("..") || value.ends_with('.') {
        return Err(invalid("invalid executable image name"));
    }
    Ok(value.to_ascii_lowercase())
}

/// Validate and normalize a policy body; unknown sections pass through untouched.
pub fn validate_policy(body: &Value) -> Result<Value> {
    let Some(object) = body.as_object() else {
        return Err(invalid("policy body must be an object"));
    };
    let mut normalized = object.clone();
    let sections: [(&str, fn(&str) -> Result<String>); 2] =
        [("web_filter", normalize_domain), ("app_control", normalize_process)];
    for (section, normalize) in sections {
        let Some(settings) = normalized.get_mut(section) else { continue };
        let Some(settings) = settings.as_object_mut() else {
            return Err(AgentError::Policy(format!("{section}.blocked must be a list")));
        };
        let entries = match settings.get("blocked") {
            None => Vec::new(),
            Some(Value::Array(items)) => items.clone(),
            Some(_) => return Err(AgentError::Policy(format!("{section}.blocked must be a list"))),
        };
        if entries.len() > MAX_ENTRIES {
            return Err(invalid("policy list exceeds 10000 entries"));
        }
        let mut unique: Vec<Value> = Vec::with_capacity(entries.len());
        for entry in entries {
            let Some(text) = entry.as_str() else {
                return Err(invalid("policy entries must be strings"));
            };
            let value = Value::String(normalize(text)?);
            if !unique.contains(&value) {
                unique.push(value);
            }
        }
        settings.insert("blocked".to_owned(), Value::Array(unique));
    }
    Ok(Value::Object(normalized))
}

/// Server assignment: either a signed policy or an explicit release (version 0).
#[derive(Debug, Clone, PartialEq)]
pub struct Assignment {
    pub vdom: String,
    pub version: i64,
    pub digest: String,
    pub body: Option<Map<String, Value>>,
    pub unassigned: bool,
    /// Exact payload as received, persisted so a restart re-verifies the same bytes.
    pub raw: Value,
}

impl Assignment {
    pub fn identity(&self) -> (String, i64, String) {
        (self.vdom.clone(), self.version, self.digest.clone())
    }

    /// Effective blocking lists; a release enforces an empty policy.
    pub fn blocked_lists(&self) -> Result<(Vec<String>, Vec<String>)> {
        let body = match &self.body {
            Some(body) if !self.unassigned => validate_policy(&Value::Object(body.clone()))?,
            _ => Value::Object(Map::new()),
        };
        let list = |section: &str| -> Vec<String> {
            body.get(section)
                .and_then(|settings| settings.get("blocked"))
                .and_then(Value::as_array)
                .map(|items| items.iter().filter_map(Value::as_str).map(str::to_owned).collect())
                .unwrap_or_default()
        };
        Ok((list("web_filter"), list("app_control")))
    }
}

/// Port of `_validated_profile`: reject anything whose digest does not match its body.
pub fn validate_assignment(value: &Value) -> Result<Assignment> {
    let vdom = value.get("vdom").and_then(Value::as_str).filter(|vdom| !vdom.is_empty())
        .ok_or_else(|| invalid("invalid assignment identity"))?;
    let version = value.get("version").and_then(Value::as_i64).ok_or_else(|| invalid("invalid assignment version"))?;
    let digest = value.get("digest").and_then(Value::as_str).unwrap_or_default();
    let body = value.get("body");
    let unassigned = value.get("unassigned").and_then(Value::as_bool) == Some(true);
    if unassigned {
        if version != 0 || !matches!(body, None | Some(Value::Null)) || value.get("digest").and_then(Value::as_str) != Some("") {
            return Err(invalid("invalid policy release"));
        }
        return Ok(Assignment { vdom: vdom.into(), version, digest: String::new(), body: None, unassigned, raw: value.clone() });
    }
    let Some(Value::Object(body)) = body else {
        return Err(invalid("policy integrity check failed"));
    };
    if version <= 0 || digest != policy_digest(body) {
        return Err(invalid("policy integrity check failed"));
    }
    validate_policy(&Value::Object(body.clone()))?;
    Ok(Assignment { vdom: vdom.into(), version, digest: digest.into(), body: Some(body.clone()), unassigned, raw: value.clone() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn signed_assignment_is_verified() {
        let body = json!({"web_filter": {"blocked": ["example.com"]}});
        let digest = policy_digest(body.as_object().unwrap());
        let assignment = validate_assignment(&json!({"vdom": "Default", "version": 2, "digest": digest, "body": body})).unwrap();
        assert_eq!(assignment.blocked_lists().unwrap(), (vec!["example.com".to_owned()], vec![]));
        let tampered = json!({"vdom": "Default", "version": 2, "digest": digest, "body": {"web_filter": {"blocked": ["evil.com"]}}});
        assert!(validate_assignment(&tampered).is_err());
    }

    #[test]
    fn release_must_be_exact() {
        let release = json!({"vdom": "Empty", "version": 0, "digest": "", "body": null, "unassigned": true});
        let assignment = validate_assignment(&release).unwrap();
        assert_eq!(assignment.blocked_lists().unwrap(), (vec![], vec![]));
        assert!(validate_assignment(&json!({"vdom": "Empty", "version": 1, "digest": "", "body": null, "unassigned": true})).is_err());
        assert!(validate_assignment(&json!({"vdom": "", "version": 0, "digest": "", "unassigned": true})).is_err());
        assert!(validate_assignment(&json!({"vdom": "X", "version": true, "digest": ""})).is_err());
    }
}
