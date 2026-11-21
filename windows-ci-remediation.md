# Windows candidate CI remediation

Status: explicitly approved on 2026-11-09: "Aprovo o adendo com TDD". The five-file implementation and local validation are complete; the new hosted CI/Security/CodeQL checks are pending. Parent scope: windows-release-completion.md, approved on 2026-11-08.

## Reproduced blockers

- Security run42609462838, SAST job129133853117: environment-derived compiler executable in tools/build_catalog_acceptance.py:151. A fully mocked reproduction confirmed that spoofed SYSTEMROOT selects an attacker-controlled compiler path. This is local builder executable-path hijacking, not evidence of a remote agent compromise.
- Dependencies job129133853595: development-only minimatch10.2.6, GHSA-g3hv-75wg-m249. The [maintainer advisory](https://github.com/isaacs/minimatch/security/advisories/GHSA-g3hv-75wg-m249) identifies11.0.1 as patched; no patched10.x is available.
- Container job129133853418: APT/libapt3.0.3 and zlib vulnerabilities. [Debian APT status](https://security-tracker.debian.org/tracker/CVE-2026-109518) fixes trixie at3.0.4; [zlib DSA6613-1](https://lists.debian.org/debian-security-announce/2026/msg00532.html) fixes1:1.3.dfsg+really1.3.1-1+deb13u1. The current official python3.14-slim digest9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f has fixedAPT but still vulnerablezlib in its amd64 SBOM. Merely refreshing its digest is insufficient.

## Exact implementation scope and order

1. tests/test_catalog_sandbox.py: add mocked behavioral regressions around the real compile_fixture, separate from the existing stubbed builder fixture. Cover spoofed SYSTEMROOT, valid alternate Windows roots including spaces/Unicode and drive-root installation, API failure/truncation, compiler absence, unsupported platform/type, and cleanup on compiler failure/timeout. No real compiler, PE, MSI, OS control or source-file writes through the mocked boundary. Run focused RED and the full permitted Python suite, then commit failing tests.
2. tools/build_catalog_acceptance.py: resolve the trusted Windows directory through kernel32 GetSystemWindowsDirectoryW with explicit ctypes types and checked return length/errors. Fail closed without environment/PATH/fixed-root fallback or scanner suppression. Keep compiler arguments,90-second timeout and source cleanup. Run focused/full GREEN and scoped lint; commit separately.
3. web/package.json and web/package-lock.json: override only minimatch to11.0.1 and regenerate the lock without unrelated upgrades. Validate the full panel lint/typecheck/coverage/build and the dependency scanner. Existing failing OSV evidence is the security regression baseline; do not add implementation-mirroring tests for a reversible lockfile update.
4. Dockerfile: use the new immutable Python digest in a shared python-base stage, update only zlib1g to Debian's fixed version with no recommends and cleaned APT indexes, then derive builder/runtime from that base. Keep the Node base and scanner severity thresholds. The fixed base APT performs the update. Build and scan the resulting image, inspect the final SBOM and run its smoke checks in disposable CI infrastructure. Existing failing image scan is the baseline.
5. Push each completed logical fix to the existing draftPR13, inspect actual CI/Security/CodeQL results and record exact head/report identities in HANDOFF.md and sanitized validation evidence. No merge, release, deployment or scanner bypass.

## Constraints and risks

- Five product/test/build files above plus evidence/HANDOFF. No native agent/MSI, guest acceptance criteria, ACK90/startup120/total deadlines or workflow weakening. Catalog18 and USB26 packages remain immutable and their accepted native bytes are unchanged.
- Minimatch is a major dependency transition forced by the patched version. Prove compatibility through the existing complete panel gates; keep its use restricted to the current tooling dependency graph.
- A pinned Debian security package intentionally fails the build if that exact package is no longer obtainable; do not silently install an older vulnerable version.
- Host Python checks retain OPENEMS_SERVICE_TESTS=0 and the four documented destructive-harness deselections. Windows installation/control tests run only in disposable hosted runners or guests. Low available host RAM is not authorization to close unrelated WSL/services.
- Windows browser, publisher, session/upgrade/reboot and location guest acceptances remain pending independently; a fixed scanner does not complete them.

## Actual local results

Compiler RED commit a8b73da reproduced eight new failures in14 focused cases. The full RED suite recorded1,623passes, ninefailures,57skips and four documented deselections; the ninthfailure exposed the new Docker stage alias conflicting with the existing digest-pinning contract. Commit ffbeb7f corrected only stage names, preserving that contract and both security pins (focused6/6 passed). Compiler fix c0ae1ae passed14/14 and scoped Ruff. Its full attempt recorded1,627passes and five setup errors caused by an absent Playwright vendor cache. Installing the official Chromium runtime only in the task-local cache with browser GC disabled let the exact same five cases pass. All1,632selected checks were verified across those two attempts; this is not a single full green run. No source changed for the five-case retry.

Dependency commit8685491 changes only the required minimatch/nonrecursive-glob-match lock records; npmci, audit including dev with zero vulnerabilities, panel lint/typecheck,154tests,95.21%linecoverage and build passed. Image commit6e643d1 and alias fixffbeb7f retain the patched immutable base plus exact zlib security version. Build/Trivy/SBOM/smoke still require the new hosted checks. Native code/MSIs and every acceptance deadline remain unchanged. See [local evidence](validation/windows-ci-remediation-local-2026-11-09.json).
