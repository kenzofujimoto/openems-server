# Browser QA correction plan

Status: explicitly approved by the operator on2026-11-09 ("Aprovo o plano dos navegadores com TDD"); local implementation validated (a0aa749), generated integration and guest acceptance pending. No native/product changes or deadline increases. Run `ac0193e3c4f545fc926b3206c3e7c80b` remains failed: `validation/browser-ec50572-retry1-review-2026-11-09.json`.

## Evidence and exact scope

Chrome passed both block cases; allowed origin/title/HTTP200/TLS passed but its body assertion was stale. Firefox timed out creating an extra context. The foreign-root guard failed without an exported baseline: its exact difference/cause remain unknown, despite successful owned cleanup.

Four versioned files: `deploy/browser_acceptance_contract.mjs`, `deploy/browser_acceptance_trust.ps1`, `tests/browser_acceptance_contract.test.mjs`, `tests/test_browser_acceptance_contracts.py`. Two reusable QA modules plus tests make the executed logic reviewable in CI; a fifth behavior file adds no boundary. Integration changes only generated ignored checkers/controller, staging, manifests and evidence.

## TDD and implementation order

1. Commit failing specifications first. Reproduce the ASCII body `This domain is for use in documentation examples`, title `Example Domain`. Test wrong scheme/origin/port, non200, insecure TLS/internal-error document, wrong title/body/branding; preserve blocked title/logo/domain and HTTP-upgrade checks. Context tests accept exactly one top-level, childless, nonempty-ID `about:blank`; reject missing/multiple/nonblank/nested/malformed/oversized trees.
2. Implement the pure Node module, retaining every guard and checking that observed body prefix. Both checkers import its verified bytes. Firefox selects its fresh-profile context through `browsingContext.getTree`, with no extra tab, ambiguity retry or fallback. Preserve actual retry1 budgets:45s BiDi commands,15s connection/exit,180s global; no increase.
3. Write mocked PowerShell tests, then the function-only trust helper. Normal TLS/public-runtime Authenticode warm-up precedes baseline capture and consumes existing budgets. Persist bounded before/after thumbprints and exact added/removed differences even on failure. Any addition/removal/remaining owned root fails; reject malformed/duplicate/overflow snapshots, tolerate order only. Fake readers/network/signature/writers test ordering and failure propagation; unit tests perform no host certificate/network/PE/browser/policy/CA operations.
4. Run focused RED/GREEN, full permitted Python/Node suites, lint and PS5.1 parsing; commit implementation separately. Python invokes Node cross-platform and PowerShell AST mocks on Windows; missing configured runtimes fail, not skip. Retain four destructive-host deselections and service-test exclusion. Prepare a fresh hashed run; independently review imports/guards/provenance before guest execution and cleanup.

## Risks and finish criteria

Warm-up does not prove the predecessor's cause; later root drift still fails. Public page content and Firefox acquisition may fail again: preserve diagnostics without relaxing guards. Success requires both real three-case browser reports, exact identity and terminal trust/hosts/process cleanup. Preserve previous failures. MSI hardening, web actions/ordered rules, categories, SafeSearch and antibypass remain separate.
