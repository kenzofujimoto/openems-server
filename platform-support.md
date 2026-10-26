# F8 — Linux and macOS deployment

Approved continuation of `roadmap-v2.md`; implementation and safe contracts first, real VM acceptance at the end.

1. Add read-only Linux network observations and real upstream discovery, including the systemd-resolved stub case. Test IPv4/IPv6, missing data, and malformed input before implementation.
2. Add a root-only `openems-platform` helper. Route DNS through an owned systemd-resolved drop-in; keep a private journal, restore after failure/crash, and refuse concurrent edits. NetworkManager-only DNS remains unsupported until a reversible backend is available.
3. Translate supported storage allow/block policies to USBGuard and executable path/SHA-256 denials to fapolicyd. Preserve unrelated rules; refuse conflicting precedence or unsupported read-only, publisher, name, and per-app network rules. No success ACK for unsupported policy.
4. Build Debian packages from matching ELF binaries; use native `rpmbuild` for RPM or fail explicitly if unavailable. Install a hardened systemd unit; keep enrollment/configuration separate from package installation. Tests inspect actual archives and script refusal paths.
5. Supply macOS launchd and signed-package build sources for the existing compatibility mode. Full DNS/USB/application pre-execution enforcement remains blocked on a Mac, Apple Developer ID, and approved Network Extension/Endpoint Security entitlements.
6. Run local parser/transaction/package tests; compile/test in a disposable Linux container where available. Real systemd routing, reboot, USBGuard, and fapolicyd require a disposable Linux VM; macOS requires a Mac. Do not modify the development host.

Constraints: no Python runtime on endpoints; no service/DNS/USB changes on this host; no CI or production deployment. Native helpers own only their files and keep journals when cleanup cannot safely restore state.

Sources: [systemd service cleanup](https://www.freedesktop.org/software/systemd/man/261/systemd.service.html), [systemd-resolved routing](https://www.freedesktop.org/software/systemd/man/251/systemd-resolved.service.html), [USBGuard rules](https://usbguard.github.io/documentation/rule-language), [fapolicyd rules](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/security_hardening/assembly_blocking-and-allowing-applications-using-fapolicyd_security-hardening), [Apple Endpoint Security entitlement](https://developer.apple.com/documentation/BundleResources/Entitlements/com.apple.developer.endpoint-security.client).
