# Align the inventory test with its existing background budget

Status: explicitly approved by the operator on2026-11-09 ("Aprovo o ajuste com TDD"); local implementation validated (9a9f290). Hosted inventory remains pending because the next workflow encountered an internal GitHub error before creating its job.

## Evidence

- First PR run42609462979: inventory CLI killed after90seconds;434other Windows-only tests passed.
- Corrected-head run42661726659: same inventory CLI killed after90seconds;448other Windows-only tests passed.
- tests/test_native_controls.py retained its90second subprocess timeout from942fffc(25/10). Native background inventory already has600seconds per collection since da5ad89(30/10), with applications and USB collected sequentially. Enforcement and policy ACK use separate unchanged budgets.
- One pinned local read-only diagnostic completed in54.165seconds with exit0,234applications/8USBdevices, valid caps and no control journals. Its collector's original failure (unexpected inventory cache) is preserved and explained in a side review. Local timing does not establish the hosted duration or identify its slow phase.

## Exact scope and TDD

1. Change only tests/test_native_controls.py, plus HANDOFF/evidence. First add three mocked regressions: a legitimate121second inventory can finish inside the documented background budget; an unrelated short command still times out at90seconds; inventory exceeding its own outer cap still times out. No sleeps, real executable, service, network or endpoint control in these three tests.
2. Run focused RED and the permitted complete local suite with the isolated Playwright cache, preserving failures; commit the failing specs separately.
3. Give invoke an optional timeout that defaults to90seconds. Pass a bounded outer budget of two existing600second collections plus60seconds transport margin (1,260seconds) only from the inventory integration test. Keep every return-code, JSON-shape, count-cap and journal-absence assertion intact. Record actual inventory duration as sanitized JUnit metadata.
4. Run focused/full validation and push to the same draftPR13. Require the actual hosted inventory to return successfully before its bound. If the product returns an internal timeout/error, the test must still fail; investigate rather than expand the cap. Record the measured hosted duration when available.

## Constraints

- No Rust, MSI, product timeout, ACK90, enforcement120, fixture15second limit, scanner threshold or skip/deselection changes.
- The larger outer inventory wait reflects an existing background contract; it does not establish an acceptable enforcement delay or claim the previous runner failure was harmless.
- Host suites retain OPENEMS_SERVICE_TESTS=0 and the four documented destructive-harness deselections. The real inventory diagnostic is read-only; no installation/control tests run on the development host.
- Application run28 and browser retry1 remain failed. Their separate guest/fixture diagnoses are not solved or reclassified by this test change.
