//! Browser DoH policies against a simulated registry; the machine registry is never touched.
use openems_agent::browser_policy::{self, RegValue, Registry, SETTINGS};
use openems_agent::error::{AgentError, Result};
use std::collections::BTreeMap;

#[derive(Default)]
struct Fake {
    values: BTreeMap<(String, String), RegValue>,
    fail_sets: usize,
}

impl Registry for Fake {
    fn get(&mut self, key: &str, name: &str) -> Result<Option<RegValue>> {
        Ok(self.values.get(&(key.to_owned(), name.to_owned())).cloned())
    }
    fn set(&mut self, key: &str, name: &str, value: &RegValue) -> Result<()> {
        if self.fail_sets > 0 {
            self.fail_sets -= 1;
            return Err(AgentError::Local("simulated registry failure".into()));
        }
        self.values.insert((key.to_owned(), name.to_owned()), value.clone());
        Ok(())
    }
    fn delete(&mut self, key: &str, name: &str) -> Result<()> {
        self.values.remove(&(key.to_owned(), name.to_owned()));
        Ok(())
    }
}

fn value(registry: &Fake, key: &str, name: &str) -> Option<RegValue> {
    registry.values.get(&(key.to_owned(), name.to_owned())).cloned()
}

const CHROME: &str = r"SOFTWARE\Policies\Google\Chrome";
const EDGE: &str = r"SOFTWARE\Policies\Microsoft\Edge";

#[test]
fn settings_disable_doh_in_chrome_edge_and_firefox_and_trust_machine_roots_in_firefox() {
    let expected = [
        (CHROME, "DnsOverHttpsMode", RegValue::Text("off".into())),
        (EDGE, "DnsOverHttpsMode", RegValue::Text("off".into())),
        (r"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Enabled", RegValue::Dword(0)),
        (r"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Locked", RegValue::Dword(1)),
        (r"SOFTWARE\Policies\Mozilla\Firefox\Certificates", "ImportEnterpriseRoots", RegValue::Dword(1)),
    ];
    let actual: Vec<_> = SETTINGS.iter().map(|setting| (setting.key, setting.name, setting.value())).collect();
    assert_eq!(actual, expected);
}

#[test]
fn ensure_applies_once_and_restore_returns_to_the_previous_values() {
    let directory = tempfile::tempdir().unwrap();
    let originals = directory.path().join("browser-policies.json");
    let mut registry = Fake::default();
    registry.values.insert((CHROME.into(), "DnsOverHttpsMode".into()), RegValue::Text("automatic".into()));
    let changed = browser_policy::ensure(&mut registry, &originals).unwrap();
    assert_eq!(changed.len(), SETTINGS.len());
    for setting in SETTINGS.iter() {
        assert_eq!(value(&registry, setting.key, setting.name), Some(setting.value()));
    }
    assert!(browser_policy::ensure(&mut registry, &originals).unwrap().is_empty(), "already applied");
    browser_policy::restore(&mut registry, &originals).unwrap();
    assert_eq!(value(&registry, CHROME, "DnsOverHttpsMode"), Some(RegValue::Text("automatic".into())));
    assert_eq!(value(&registry, EDGE, "DnsOverHttpsMode"), None, "values that did not exist are deleted");
    assert!(registry.values.len() == 1 && !originals.exists());
    browser_policy::restore(&mut registry, &originals).unwrap();
}

#[test]
fn tampering_is_rewritten_without_losing_the_true_original() {
    let directory = tempfile::tempdir().unwrap();
    let originals = directory.path().join("browser-policies.json");
    let mut registry = Fake::default();
    browser_policy::ensure(&mut registry, &originals).unwrap();
    registry.values.insert((EDGE.into(), "DnsOverHttpsMode".into()), RegValue::Text("secure".into()));
    let changed = browser_policy::ensure(&mut registry, &originals).unwrap();
    assert_eq!(changed, vec![format!(r"{EDGE}\DnsOverHttpsMode")]);
    browser_policy::restore(&mut registry, &originals).unwrap();
    assert_eq!(
        value(&registry, EDGE, "DnsOverHttpsMode"),
        None,
        "restores the pre-agent state, not the tampered value"
    );
}

#[test]
fn restore_leaves_values_someone_else_changed_later() {
    let directory = tempfile::tempdir().unwrap();
    let originals = directory.path().join("browser-policies.json");
    let mut registry = Fake::default();
    browser_policy::ensure(&mut registry, &originals).unwrap();
    registry.values.insert((CHROME.into(), "DnsOverHttpsMode".into()), RegValue::Text("secure".into()));
    browser_policy::restore(&mut registry, &originals).unwrap();
    assert_eq!(value(&registry, CHROME, "DnsOverHttpsMode"), Some(RegValue::Text("secure".into())));
}

#[test]
fn originals_are_saved_before_the_first_write() {
    let directory = tempfile::tempdir().unwrap();
    let originals = directory.path().join("browser-policies.json");
    let mut registry = Fake { fail_sets: 1, ..Fake::default() };
    registry.values.insert((CHROME.into(), "DnsOverHttpsMode".into()), RegValue::Text("automatic".into()));
    assert!(browser_policy::ensure(&mut registry, &originals).is_err());
    assert!(originals.exists(), "a crash after a write must still know what to restore");
    browser_policy::ensure(&mut registry, &originals).unwrap();
    browser_policy::restore(&mut registry, &originals).unwrap();
    assert_eq!(value(&registry, CHROME, "DnsOverHttpsMode"), Some(RegValue::Text("automatic".into())));
}

/// Read-only probe of the real registry: missing keys are absent and REG_SZ values decode.
#[cfg(windows)]
#[test]
fn machine_registry_reads_without_writing() {
    let mut registry = browser_policy::WindowsRegistry;
    assert_eq!(registry.get(r"SOFTWARE\openems-agent-test-missing", "Value").unwrap(), None);
    let build = registry.get(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild").unwrap();
    assert!(
        matches!(build, Some(RegValue::Text(text)) if text.chars().all(|c| c.is_ascii_digit()) && !text.is_empty())
    );
}
