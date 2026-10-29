# WDAC single-hash catalog-scope investigation

Status: isolated comparison 39 completed successfully after the operator said
"continue" on 2026-10-29. The operator then explicitly approved integrating the
concrete single-hash patch below with TDD. Integration committed as 959e9de;
separate frozen package prepared. Real acceptance pending ACCEPT-WDAC-40.

## Confirmed observations

- Source 2100dd7, real acceptance shortcut 36, failed waiting for the hash v4 ACK.
  Five initial checks passed. There was no v4 ACK, positive or negative.
- The release policy file was last written at 14:00:45.517 UTC. The OpenEMS CI
  load event occurred at 14:01:09.932 UTC, 24.415 seconds later. The applied
  event followed at 14:01:10.632 UTC. The deployment was late for the original
  90-second ACK window. Hash/rename denial was never exercised.
- Preserved private copy created 13:59:32.819 UTC; generated hash XML created
  14:01:08.459 UTC: 95.640 seconds between them. This is a file-timestamp span,
  including post-copy checks and generation, not an instrumented cmdlet time.
- Repeated normal Get-AuthenticodeSignature queries took 276 ms and 5 ms.
  Both returned NotSigned and preserved the file hashes. They can benefit from
  caches and are not a replay of the original production timings.
- Release v5 ACK and normal MSI removal completed. Read-only SYSTEM diagnostic
  found no service, watchdog, agent process, managed NRPT, journals or active
  OpenEMS CI policy. Fourteen existing policies were listed. Private XML/CIP
  artifacts remain preserved for investigation.

Evidence:
`validation/windows-controls-vm-2100dd7-2026-10-29.json`,
`validation/vm-applications-fixed-2100dd7-diagnostic-2026-10-29.json`,
`validation/vm-applications-fixed-2100dd7-stage-timing-2026-10-29.json`.

## Hypotheses, not established causes

1. ConfigCI catalog discovery contributes most of the post-copy delay despite a
   single private PE scan. A private catalog path may bound that extra work.
2. ConfigCI/OS initialization or other scan processing remains expensive even
   with a private catalog path. The comparison may show no improvement.
3. Work queued before enforcement and status-report scheduling add latency.
   A faster producer still needs a real end-to-end ACK test.

The ConfigCI syntax exposes PathToCatroot. Microsoft documents the catalog path
for remote/mounted scans; it does **not** document an empty private catalog as a
performance recommendation. The empty-directory case below is experimental.

## Proposed steps

1. Keep the current disposable guest intact. Authenticate the preserved fixture
   by source-MSI hash and inventory SHA-256. Use the saved 2100dd7 policy XML as
   the reference; copy it before any normalization.
2. In a new SYSTEM-private diagnostic directory, prepare one verified sample
   and an empty private catalog directory. Reuse the unchanged source validation
   functions, including the existing normal signature query and post-copy
   SHA-256 checks. Do not modify Windows CatRoot, certificates, trust settings,
   antivirus, TLS, journals, services or existing policies.
3. Generate only private XML with the same single-hash ConfigCI flags plus
   `-PathToCatroot <private-empty-directory>`. Measure complete preparation,
   scan, validation, merge, normal option normalization and private CIP conversion
   separately and together. Keep a hard 120-second child stop. No OS policy load.
4. Require the same genuine UMCI deny hashes, user references, no kernel denies,
   allow scope, signer scope and normalized options as the real 2100dd7 reference.
   Preserve normal Authenticode checks; do not use this catalog choice for
   publisher/name/path/multiple-rule routes. Reject missing/changed rules.
5. Proceed only on exact equivalence and clear timing headroom. Target complete
   private preparation/generation under 30 seconds to leave room for the rest
   of the observed pipeline; this is an internal experiment gate, not a relaxed
   acceptance deadline. No speed improvement is assumed. Otherwise preserve
   the result and propose a different path before product changes.
6. If validated, commit failing mocked regressions first for the bounded private
   catalog argument, directory ownership/scope, unchanged identity/signature
   validation, empty/kernel/widened XML rejection and untouched fallback routes.
   Implement the smallest single-hash adapter/mocks change, then run all permitted
   host suites (four whole-harness cases deselected).
7. Freeze a new separate MSI/ISO after checks, keep earlier inputs immutable and
   repeat the complete real WDAC acceptance in clean UID 2. The ACK must arrive
   within the unchanged 90 seconds, and real pre-execution denial, rename,
   publisher, release and removal must pass. No push, PR, merge or CI change.

## Risks and stop conditions

- Catalog lookup can affect identity metadata. Exact hash/output comparison is
  mandatory, and this proposal is limited to the already verified hash selector.
  Publisher and other selector behavior remains unchanged.
- The empty catalog path may fail or leave the scan equally slow; that rejects
  the strategy. Do not skip validation or synthesize UserMode flags.
- A fast isolated comparison cannot guarantee scheduling/ACK performance. Keep
  final acceptance separate; no additional warm-up before the real clean round.
- Preserve existing artifacts and no-agent state; never force removal or alter
  service permissions. Do not restore the current guest until evidence is saved
  and the next concrete step calls for a clean snapshot.

Primary references:
[New-CIPolicy](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy?view=windowsserver2025-ps),
[Get-SystemDriver PathToCatroot](https://learn.microsoft.com/en-us/powershell/module/configci/get-systemdriver?view=windowsserver2025-ps#-pathtocatroot).

## Successful comparison 39

- Original sanitized result:
  `validation/vm-applications-fixed-2100dd7-catalog-comparison-2026-10-29.json`;
  SHA-256 `7310af0b52b8dcf7be5a12b08010c812f0c8f1580b14317816a04f501f5f907e`.
- Original adapter validation functions were included by source SHA-256; normal
  signature verification and post-copy hash checks remained enabled.
- Sample preparation 637 ms; New-CIPolicy with private catalog 2,663 ms;
  complete private preparation/generation/validation/conversion 8,225 ms.
- All eight exact reference checks passed; four real UMCI hash denies, allow
  and signer scope/options preserved; all 14 CI policy IDs unchanged.
- No agent installation or OS policy loading. This is not the real ACK test.

## Concrete integration proposed for approval

1. Commit failing tests first: the single-hash New-CIPolicy call must receive
   PathToCatroot pointing to a fresh empty SYSTEM-private directory under the
   adapter's owned work area. Verify no Windows catalog or unrelated path is
   changed, existing sample/signature checks remain, and fallback rules do not
   receive the alternative catalog argument.
2. Make the minimum change only in deploy/agent-applications.ps1 and its mocks:
   create/protect that fresh directory in the existing single-hash branch and
   pass it to New-CIPolicy. Retain the strict XML validator, private AllowAll,
   option normalization, ownership journal and all current failure handling.
3. Run the full permitted Python/Rust/panel suites and lint checks. Host Windows
   operations remain mocked and four whole-harness cases remain deselected.
4. Build a separate frozen MSI/ISO only after validation; then repeat full WDAC
   once in clean UID 2. No additional manual generation-only collectors planned
   before that round. If a new failure occurs, preserve it and reassess scope.

Risk: catalog lookup can affect metadata, so this stays limited to the validated
single-hash case; publisher/name/multiple rules remain unchanged. Require the
unchanged real 90-second ACK deadline and actual pre-execution denial. No bypass
of TLS, antivirus, signature validation or tamper protection; no push/PR/CI.

## Integration and delivery record

- Red b26708b: 1 failure/58 passes; green adapters 59/59. Product 959e9de.
- Complete Python suite: 1,159 passes, one unchanged native-inventory timeout at
  90 seconds, 58 skips/four whole-harness cases deselected. Isolated repeat passed
  in 77.14 seconds; full suite is not reported green. Rust 225/panel 102 and
  fmt/Clippy/lint/typecheck/release passed. Existing Ruff/coverage gates remain.
- Validation: `validation/windows-wdac-catalog-fix-2026-10-29.json`.
  Package: `validation/windows-wdac-catalog-package-2026-10-29.json`.
- `openems-controls-fixed-959e9de.iso`, source frozen at 959e9de, requires clean
  snapshot UID 2 and ACCEPT-WDAC-40. All previous inputs preserved. This next
  run is full acceptance; no additional generation-only collector requested.
