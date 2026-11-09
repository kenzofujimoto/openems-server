# Identify the applications fixture timeout without relaxing acceptance

Status: explicitly approved by the operator on2026-11-09 ("Aprovo a instrumentação com TDD"); local implementation validated (b118f30), instrumented guest acceptance pending. Run28 remains failed (three checks). Collector29 verified the original identity and owned cleanup, but does not establish the timeout's cause.

## Evidence

The network policy ACK was positive at12:07:52.4392818Z. The control-copy marker was last modified at12:07:00.6690088Z, before that ACK; the selected network marker is absent. The legacy script invokes the selected executable first, deletes its old marker and waits15seconds. It exports neither an invocation identity nor process-start/first-instruction/exit timings. These facts localize the interrupted branch but do not establish DNS, CLR startup, scheduling or filtering as the cause.

## Scope and order

1. Change only `tests/test_controls_fixture_backend.py` and `deploy/test-controls-sandbox.ps1`, plus this plan/HANDOFF/evidence. Add mocked failing specifications first for selected/control invocation identity, successful/failed/timeout process outcomes, bounded receipt persistence on exceptions, cleanup and unchanged15second/ACK90 limits. Extract trusted functions only; mock process launch/wait/kill and use inert owned files. Never compile or run fixture PEs or apply controls on the host. Commit RED after focused and complete permitted validation.
2. Introduce a small mockable process-start boundary and bounded per-probe lifecycle receipts: approved fixture basename/hash, selected/control phase, request/start-return/finish timestamps, elapsed time, first-instruction marker presence, exit/native-error/timeout and owned cleanup. No credentials, arbitrary URLs, process arguments or unbounded stdout/stderr. Preserve failures when receipt export fails.
3. The owned C# fixture records bounded phase markers at entry, immediately before the existing request and after its response. Keep the same synchronous request, TLS validation, URL and8000ms request setting. Preserve the existing15000ms process wait, cleanup behavior, hash/publisher/renamed-copy checks and all acceptance criteria. This is observability, not a claimed product fix.
4. Focused GREEN, full permitted suite, Ruff and Windows PowerShell5.1 parsing; commit separately. Build a new hashed ISO using the frozenec50572 MSI pair and a unique run directory. Preserve run28 and diagnostic29 bytes. Repeat once in the clean disposable VM; inspect any new failure's phase receipts before proposing a behavioral change. A missing/late probe, nonzero cleanup, reboot-required or unobserved criterion remains failed/pending.

## Risks and constraints

Marker I/O may itself fail, and process creation can stall before managed code; record what was observed without inventing a cause. Never increase timeouts or substitute positive ACKs for real execution/network behavior. Native sources/MSIs, catalog18 and USB26 evidence remain unchanged. No endpoint operations on the development host. Actual completion still requires all applications criteria and verified removal in the guest.
