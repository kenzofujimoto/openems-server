use openems_agent::https_blockpage::BlockedDomains;

#[test]
fn certificates_are_limited_to_exact_redirected_domains_and_release_revokes() {
    let domains = BlockedDomains::default();
    assert!(!domains.contains("example.com"));
    domains.replace(&["example.com".into()]).unwrap();
    assert!(domains.contains("example.com"));
    assert!(domains.contains("www.example.com"));
    for name in ["allowed.com", "sub.example.com", "127.0.0.1", "example.com.", "https://example.com"] {
        assert!(!domains.contains(name), "{name}");
    }
    assert!(domains.replace(&["*.example.com".into()]).is_err());
    assert!(domains.contains("example.com"));
    domains.replace(&[]).unwrap();
    assert!(!domains.contains("example.com"));
}
