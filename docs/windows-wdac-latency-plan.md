# WDAC latency investigation — proposed follow-up

Status: approved explicitly by the operator on 2026-10-29. Generation-only
comparison authorized; no implementation of this alternative yet.

## Evidence and completed authorized work

- The expanded guest comparison generated four genuine user-mode deny rules,
  private XML and CIP. All 14 existing Code Integrity policy IDs remained equal.
- Total elapsed time was 97,826 ms; Get-SystemDriver alone took 90,125 ms.
  This fits the 120-second generation probe but does not meet the unchanged
  90-second policy ACK deadline. It is not an enforcement acceptance result.
- Correctness TDD is implemented in ad3e6d4 after red commits 1c49c25/b8f0eda.
  The adapter scans current verified private copies once, requires one matching
  user-mode DriverFile per sample, rejects conflicting identities and keeps only
  genuine user-mode rules. Forty-three mocked adapter tests passed.
- Complete permitted host verification passed: 1,144 Python tests, 58 skips and
  four whole-harness cases deselected; 225 Rust tests and 102 panel tests, plus
  fmt/Clippy/lint/typecheck. Aggregate Python coverage is 88.58%; module coverage
  gates remain pending. Full Ruff retains one unchanged Linux S603 finding.
- Earlier no-user-mode-rule diagnostic results used wrapped collection filters;
  they cannot by themselves prove that the direct production cmdlet returned
  only kernel rules. The generation timing remains an observed limitation.

## Proposed steps

1. In the current disposable guest, reuse only the authenticated fixture and
   copy it into a new SYSTEM-private directory. No agent installation or policy
   loading. Preserve every previous result.
2. Measure the documented New-CIPolicy -ScanPath <private-directory> -UserPEs
   -Level Hash -Deny -NoScript -NoShadowCopy -MultiplePolicyFormat path, including
   XML validation and private CIP conversion. Record wall time, process CPU time,
   sample SHA-256 and CI policy IDs before/after. Run bounded cases separately;
   each child retains a hard 120-second stop. Do not increase ACK or runner limits.
3. Verify that only the intended private sample contributes deny hashes, that
   the user-mode signing scenario references real deny rules and that no extra
   kernel deny scope or unrelated target is introduced. Check the resulting
   private policy against the current AllowAll-plus-deny construction.
4. Proceed only if the alternative is correct and leaves enough time for the
   complete policy/ACK path inside 90 seconds. Similar scan latency is possible;
   no speed improvement is promised. Otherwise preserve the result and propose
   another path before modifying production.
5. If validated, commit failing regression tests for the alternative first,
   implement the smallest adapter/mocks change, and run all permitted host checks.
   Only then build a separate frozen package and repeat real WDAC acceptance in
   a clean snapshot. Keep the web-table feature in its separate branch.

## Risks and constraints

- A different XML producer may alter signing scenarios or implicit defaults.
  Reject widened targets, missing UMCI, empty deny sets and kernel-only output.
- A generation-only comparison is not proof of pre-execution denial. Hash,
  publisher, rename, release and cleanup still require the full real acceptance.
- No synthetic UserMode flags, weakened certificate checks, AV changes, service
  permission changes, deadline increases or forced removal.
- No push, PR, CI change, overwritten package or unapproved product change.

Reference: [Microsoft New-CIPolicy documentation](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy?view=windowsserver2025-ps).
The documented scan performs work similar to Get-SystemDriver; the experiment
must establish its behavior and cost rather than assume it is faster.

## Prepared comparison

- Shortcut 34 runs `probe-wdac-direct-policy.ps1` inside the current guest.
- Helper SHA-256: `4a8ac4bcf8a8c6e4d8eced11e0015b28164200db9eef9eeb207b5f5efaa41711`.
- Output: `fixed-918aba2/wdac-direct-policy-probe.json`; never overwrite a report.
- PowerShell 5.1 parser and six pure XML/scope checks passed on the host. These
  checks loaded only pure XML helpers: no ConfigCI, controller, MSI or controls.
- The candidate must preserve the four authenticated reference deny hashes,
  user-mode references, allow scope, signer scope and normalized production
  options. Record failed comparisons instead of weakening those requirements.
- Await operator execution; no snapshot restore or ISO change needed.
