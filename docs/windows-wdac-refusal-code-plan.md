# Recognize Windows integrity-policy denial 4551

Status: explicitly approved by the operator on 2026-10-29, including completing
USB acceptance afterward. TDD in progress; same frozen 959e9de MSIs required.

## Confirmed defect

- Full acceptance 40 used the frozen 959e9de MSI/executable with correct hashes.
  Hash assignment v4 received a successful ACK within the unchanged deadline.
- The first execution attempt returned native_error 4551, started false, exit -1.
  Assert-ExecutionDenied failed because its allowlist contains only 577 and 1260
  (deploy/test-controls-sandbox.ps1:374).
- The installed Microsoft Windows SDK 10.0.26100.0 shared/winerror.h:14526 defines
  ERROR_SYSTEM_INTEGRITY_POLICY_VIOLATION as 4551L. Microsoft's generated enum
  also defines this exact mapping. This is a separate harness recognition defect.
- No retrospective pass: renamed-image, publisher, release-after-denial and full
  final ownership checks were not reached. Retain the original failed report.
- Final release v5 ACK and normal removal completed with no cleanup errors;
  service/watchdog/processes/managed NRPT/journals absent in the supplement.
  Per-policy CI events have not yet been collected for this round.

## Minimal approved-work proposal

1. Add and commit failing tests that AST-extract only Assert-ExecutionDenied,
   mock Invoke-Fixture and use temporary sentinels. Never invoke the complete
   acceptance harness, real processes, MSI, ConfigCI or OS controls on the host.
2. Require 4551 with started=false to be accepted alongside existing 577/1260.
   Keep rejection of started=true, successful execution, generic access denied,
   unrelated errors and reputation/antivirus codes. Do not allow a numeric range.
3. Add only 4551 to the existing explicit allowlist; retain the sentinel and all
   other acceptance scenarios, checks, timeout and cleanup behavior.
4. Run the full permitted host suite with the four whole-harness cases deselected.
   Keep the existing native-inventory/coverage/Ruff limitations explicit; no
   unrelated inventory, antivirus, TLS or CI fixes in this patch.
5. Reuse exactly the frozen 959e9de production MSIs and native binaries. Do not
   rebuild or replace them. Prepare a separate harness/media package with new
   file hashes and separate agent/harness revision metadata; preserve all old
   media and original results.
6. Include sanitized Code Integrity event and current-policy collection in the
   next acceptance launcher automatically, using read-only queries after the
   run. Do not ask for a separate manual diagnostic collector. Failure to read
   evidence must be reported, never silently converted to acceptance.
7. Repeat the complete real acceptance once in clean UID 2 with the new media.
   Original/renamed/publisher denial must occur before the first instruction,
   release must restore launch, removal must preserve unrelated policies. Do
   not mark the current failed run passed after editing the harness.

## Risk and boundaries

Recognizing a wrong error could produce false acceptance. The exact SDK-defined
4551 mapping, negative cases and the unchanged no-start sentinel guard bound
that risk. The next run will export CI event IDs, policy GUIDs and fixture
association without raw secrets or user paths. Agent behavior and MSI bytes
remain unchanged. No push, PR, merge or CI change.

Primary source:
[Microsoft generated WIN32_ERROR enum](https://source.dot.net/Microsoft.Private.Windows.Core/Generated/Basic.CompilerLog.Util/Basic.CompilerLog.Util.Impl.BasicGeneratedFilesAnalyzerReference/Windows.Win32.WIN32_ERROR.g.cs.html).
Local primary SDK: C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/shared/winerror.h:14526.
