//! Recoverable installer transaction. Tests use an isolated backend, never machine trust.

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[derive(Default)]
    struct Fake {
        roots: BTreeSet<Vec<u8>>,
        restored: bool,
        fail_restore: bool,
    }
    impl TransactionBackend for Fake {
        fn trusted(&mut self, root: &[u8]) -> Result<bool> { Ok(self.roots.contains(root)) }
        fn trust(&mut self, root: &[u8]) -> Result<()> { self.roots.insert(root.to_vec()); Ok(()) }
        fn untrust(&mut self, root: &[u8]) -> Result<()> { self.roots.remove(root); Ok(()) }
        fn restore(&mut self, _: &[FileSnapshot]) -> Result<()> {
            if self.fail_restore { return Err(failure("restore failed")); }
            self.restored = true; Ok(())
        }
    }
    fn journal(before: Option<&[u8]>, trusted: bool, active: Option<&[u8]>) -> Journal {
        Journal { version: 1, config: "agent.json".into(), files: vec![], root_before: before.map(Vec::from),
            trusted_before: trusted, root_active: active.map(Vec::from) }
    }
    #[test]
    fn rollback_removes_only_new_root_and_preserves_unrelated_roots() {
        let mut backend = Fake::default();
        backend.roots.extend([b"ours".to_vec(), b"unrelated".to_vec()]);
        restore_transaction(&journal(None, false, Some(b"ours")), &mut backend).unwrap();
        assert_eq!(backend.roots, BTreeSet::from([b"unrelated".to_vec()]));
        assert!(backend.restored);
    }
    #[test]
    fn rollback_preserves_preexisting_trusted_authority() {
        let mut backend = Fake::default(); backend.roots.insert(b"ours".to_vec());
        restore_transaction(&journal(Some(b"ours"), true, Some(b"ours")), &mut backend).unwrap();
        assert!(backend.roots.contains(b"ours".as_slice()));
    }
    #[test]
    fn rollback_removes_new_trust_for_existing_untrusted_authority() {
        let mut backend = Fake::default(); backend.roots.insert(b"ours".to_vec());
        restore_transaction(&journal(Some(b"ours"), false, Some(b"ours")), &mut backend).unwrap();
        assert!(backend.roots.is_empty()); assert!(backend.restored);
    }
    #[test]
    fn uninstall_rollback_restores_existing_root_and_is_repeatable() {
        let mut backend = Fake::default();
        let saved = journal(Some(b"ours"), true, Some(b"ours"));
        restore_transaction(&saved, &mut backend).unwrap();
        restore_transaction(&saved, &mut backend).unwrap();
        assert_eq!(backend.roots, BTreeSet::from([b"ours".to_vec()]));
    }
    #[test]
    fn restore_failure_is_reported_for_retry() {
        let mut backend = Fake { fail_restore: true, ..Fake::default() };
        assert!(restore_transaction(&journal(None, false, None), &mut backend).is_err());
    }
}
