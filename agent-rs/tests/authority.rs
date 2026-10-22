use openems_agent::authority::Authority;
use rustls::pki_types::{ServerName, UnixTime};
use rustls::{RootCertStore, client::WebPkiServerVerifier, client::danger::ServerCertVerifier};
use std::sync::Arc;
#[test]
fn rejects_invalid_names_and_signs_only_its_own_roots() {
    let ca = Authority::ephemeral().unwrap();
    for name in ["* .com", "*.example.com", "127.0.0.1", "localhost", "example.com/path", "EXAMPLE.COM"] {
        assert!(ca.issue(name).is_err());
    }
    let leaf = ca.issue("example.com").unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.root_der()).unwrap();
    let verify = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .unwrap();
    assert!(
        verify
            .verify_server_cert(&leaf.cert[0], &[], &ServerName::try_from("example.com").unwrap(), &[], UnixTime::now())
            .is_ok()
    );
    assert!(
        verify
            .verify_server_cert(
                &leaf.cert[0],
                &[],
                &ServerName::try_from("other.example.com").unwrap(),
                &[],
                UnixTime::now()
            )
            .is_err()
    );
    let stranger = Authority::ephemeral().unwrap().issue("example.com").unwrap();
    assert!(
        verify
            .verify_server_cert(
                &stranger.cert[0],
                &[],
                &ServerName::try_from("example.com").unwrap(),
                &[],
                UnixTime::now()
            )
            .is_err()
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ca");
    std::fs::write(&path, b"corrupt").unwrap();
    assert!(Authority::load_or_create(&path).is_err());
}

#[test]
fn certificate_constraints_and_validity_are_narrow() {
    use x509_parser::prelude::FromDer;
    let ca = Authority::ephemeral().unwrap();
    let der = ca.root_der();
    let (_, root) = x509_parser::certificate::X509Certificate::from_der(der.as_ref()).unwrap();
    assert_eq!(root.basic_constraints().unwrap().unwrap().value.path_len_constraint, Some(0));
    let usage = root.key_usage().unwrap().unwrap();
    assert!(usage.value.key_cert_sign());
    assert!(usage.value.crl_sign());
    assert!(!usage.value.digital_signature());
    let issued = ca.issue("example.com").unwrap();
    let (_, leaf) = x509_parser::certificate::X509Certificate::from_der(issued.cert[0].as_ref()).unwrap();
    assert!(!leaf.is_ca());
    assert!(leaf.extended_key_usage().unwrap().unwrap().value.server_auth);
    assert!(!leaf.extended_key_usage().unwrap().unwrap().value.client_auth);
    assert!(leaf.validity().not_after.timestamp() - leaf.validity().not_before.timestamp() <= 86400);
    assert!(leaf.validity().not_after <= root.validity().not_after);
}
