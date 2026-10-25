# Desktop roadmap completion (F4, F3, F7/F2, F8)

Authorized by the user's request to continue through the last desktop phase; F9 remains excluded.
The previous agreement to defer all Sandbox acceptances remains in force.

1. Inspect the current policy, runtime, API, legacy console and packaging; agree on shared USB,
   application and inventory contracts across the native agent, Python reference and panel.
2. Add failing policy vectors and native control tests, then implement storage-only USB selection,
   Windows restrictions/read-only enforcement, owned-state journals and cleanup. Preserve HID devices.
3. Add failing application-control contracts, then implement inventory, verified local samples for
   WDAC execution denial, per-executable firewall rules and reversible removal. Never claim an ACK
   for unsupported enforcement or a policy awaiting a reboot.
4. Add authenticated persistent inventory/control-event endpoints and management APIs; complete
   web policy, rule, audit, invitation, administrator and installer workflows with CSRF and role checks.
5. Complete the React screens with keyboard access, mobile navigation and persisted dark mode;
   remove the legacy console after parity, and verify the real Docker image can start.
6. Implement and package Linux systemd/DNS/USBGuard/fapolicyd support with capability checks and
   rollback. Add feasible macOS launchd/package support; list signed extension dependencies explicitly.
7. Build safe Sandbox harnesses, a physical-USB VM acceptance and Linux VM instructions. Every
   missing device, unsupported OS capability or unperformed manual check remains visibly pending.
8. Freeze the code, run complete local suites and disposable database/container checks, rebuild
   all pending MSI inputs from the same release, and record exact test commands in ACCEPTANCE.md
   and pending status in HANDOFF.md. CI and real Sandbox runs remain deferred.

## Constraints and verification

- TDD: reproduce a failing behavioral contract before each implementation, with separate conventional
  test and implementation commits. Shared policy vectors verify Python/Rust parity.
- No USB, WDAC, firewall, DNS, service or trust mutations on the development host. Unit tests use
  fakes; actual changes run only in disposable guests. Own only explicitly journaled state.
- Windows WDAC support and reboot/removal behavior depend on OS version; raw file SHA-256 is not
  an Authenticode policy hash. Require and verify a local sample before generating its WDAC rule.
- Windows Sandbox cannot substitute a shared folder for physical USB. USB hardware acceptance
  requires a disposable VM with passthrough. Linux acceptance requires a Linux guest.
- macOS Network Extension/Endpoint Security, signing and notarization require a Mac and Apple
  permissions; no stub or package is evidence that those controls have been accepted.
- Final checks: Python suite excluding destructive host tests, Rust fmt/clippy/tests/release,
  React tests/coverage/lint/types/build, PostgreSQL contracts and a disposable Docker smoke test.
