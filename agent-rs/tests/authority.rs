use openems_agent::authority::Authority;
#[test]
fn rejects_invalid_names_and_corrupt_store() {
 let dir=tempfile::tempdir().unwrap(); let path=dir.path().join("ca");
 let ca=Authority::load_or_create(&path).unwrap();
 for name in ["* .com", "*.example.com", "127.0.0.1", "localhost", "example.com/path", "EXAMPLE.COM"] {assert!(ca.issue(name).is_err());}
 assert!(ca.issue("example.com").is_ok());
 let fingerprint=ca.fingerprint();
 assert_eq!(Authority::load_or_create(&path).unwrap().fingerprint(), fingerprint);
 std::fs::write(&path,b"corrupt").unwrap();
 assert!(Authority::load_or_create(&path).is_err());
}
