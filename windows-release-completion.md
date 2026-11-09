# Windows release completion

Goal: consolidate the verified Windows candidate, repeat acceptance still tied to older binaries, and prepare a draft PR with actual CI results. The operator requested this closure on 2026-11-08 ("termine então").

Status: detailed scope explicitly approved on 2026-11-08: "Aprovo o fechamento". Draft PR13 is open. Hosted CI, Security and CodeQL passed at7e84493; current-package catalog, physical USB, session/upgrade/real-reboot and network locations acceptance passed. Applications and complete browser acceptance remain pending. See ACCEPTANCE.md and the dated validation reviews; previous failed attempts remain failed.

## Steps

1. Freeze the accepted production MSI pair from ec50572, hashes c1e38743… and eba1fc2e…, and preserve catalog run18 and physical USB run26. Verify the native source diff to HEAD is empty, including embedded PowerShell and DoH input. Do not rebuild accepted binaries unnecessarily.
2. Add a current evidence matrix to ACCEPTANCE.md and update roadmap-v2.md, docs/vm-acceptance-guide.md, docs/second-machine-acceptance.md and docs/README.md. Preserve historical results. Mark current catalog/USB passed; keep browsers, publisher, session/upgrade/reboot and locations tied to their original package versions until repeated.
3. Prepare isolated acceptance inputs for the missing Windows scenarios using existing verified harnesses and the frozen MSI pair. Run actual controls only in disposable guests; the operator handles UAC, guest login and any necessary restart. Keep separate run identities, input hashes, original reports and cleanup proof. If existing harnesses need source changes, propose a separate explicit scope with failing tests committed before implementation.
4. Review the full main-to-candidate diff for publication. Push the feature branch normally and open a draft PR into main. Opening the PR runs the existing CI, Security and CodeQL workflows; do not merge, release, sign or change workflow thresholds. Record exact head/base and checks.
5. Validate documentation links and evidence JSON, inspect actual CI failures, and distinguish infrastructure failures from code defects. Product/workflow fixes outside existing approved plans require a concrete TDD addendum before edits. Local host checks must keep OPENEMS_SERVICE_TESTS=0 and the four documented destructive-harness deselections.
6. Update HANDOFF.md and sanitized validation evidence after each completed acceptance/checkpoint. Finish only when the required Windows candidate checks actually pass, or report the concrete external prerequisite requiring operator action. Linux operational acceptance and macOS native extensions remain separate unfinished platform work.

## Risks and verification

- Historical browser, publisher and upgrade successes are not proof for the current MSI bytes. Do not relabel old reports or infer upgrade from the presence of the next MSI.
- CI install/service tests belong on disposable hosted runners, never the development host. No credentials, personal browser profiles or private CA keys are transferred into shared inputs or committed.
- The existing 90-second ACK and scenario deadlines remain intact. Guest failure requires evidence preservation and cleanup review before restoring a snapshot.
- Documentation-only edits use link/JSON/diff checks; no product behavior changes or redundant product-suite reruns are needed for them. Existing behavior suites and actual guest/hosted-runner acceptance verify the candidate. Any new behavior change follows the user's approved TDD workflow.
- Distribution signing, full production rollout, Linux enforcement and macOS entitlements are not implied by a draft PR or a Windows lab pass.
