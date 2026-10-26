# Linux acceptance and supported backends

This package contains native binaries, a systemd service and the `openems-platform` lifecycle helper. It never installs Python on the endpoint. Package installation does not enroll or start the agent.

After reviewing the server address and invitation, configure with `/usr/bin/openems-agent configure --server https://YOUR-SERVER --devid YOUR-DEVICE --config-path /etc/openems/agent.json --dns-filter --invitation YOUR-INVITATION`. Prefer passing the invitation through the existing `OPENEMS_INVITATION` mechanism rather than shell history. Protect configuration/state as root mode 0600 and directories as 0700. Then enable/start `openems-agent.service`. The package retains enrollment/state on removal and reinstalls.

DNS routing requires active systemd-resolved, its normal stub configuration, local port 53, and no conflicting per-link `~.` route (for example a full-tunnel VPN). An owned `/etc/systemd/resolved.conf.d/90-openems.conf` routes to the local resolver. Real upstream addresses are read from `/run/systemd/resolve/resolv.conf` and saved before redirecting; loopback servers are never used as upstreams. `ExecStopPost` removes the owned drop-in on shutdown, failure or restart. NetworkManager-only DNS routing is unsupported and is refused before changing the machine.

USB control requires USBGuard running, an explicitly configured `RuleFolder=/etc/usbguard/rules.d/`, and no active main-rule file or earlier rule that would hide the managed rule. A dedicated managed rule folder is recommended. Only storage allow/block rules by VID, PID, serial or storage class are supported. HID devices and hubs are exempted before storage rules; mixed HID/storage devices are deliberately left usable. Read-only and Windows instance IDs are unsupported and produce a failed policy application, never a success ACK. Existing USBGuard security rules are not rewritten to make a conflicting policy fit.

Pre-execution application control requires active fapolicyd and a rules.d configuration whose earlier rules do not allow execution before the managed denials. Absolute path and SHA-256 rules are supported; hashes require `integrity=sha256` in fapolicyd.conf. Publisher, name-based pre-execution and per-application network rules are unsupported. Legacy exact process-name termination remains a separate fallback.

Root can stop/remove this user-mode agent. Windows MSI anti-tamper guarantees must not be inferred for Linux. Browser DoH policies, WFP and the Windows trusted HTTPS block-page CA are not Linux capabilities. Do not configure Windows-only flags for this package.

Real acceptance requires a disposable Linux VM, not Windows Sandbox or an unprivileged build container:

1. Install/configure, verify enrollment and actual policy ACK; reboot and verify systemd restart/cache.
2. Query a blocked name and an allowed name through system DNS; stop the service and confirm normal DNS returns. Inject a failed agent start and repeat restoration.
3. Verify location CIDR/gateway/suffix signals and transitions without server contact.
4. With USB passthrough, confirm storage deny/allow by serial; verify keyboard/mouse remain usable. Unsupported read-only must fail explicitly.
5. Deny a disposable executable by hash, rename it and confirm fapolicyd still refuses execution; release it and verify access returns. Test publisher/network refusal explicitly.
6. Remove the package and confirm only owned snippets disappear, foreign DNS/policy files remain and the private state is retained. Change a managed snippet manually and verify cleanup refuses to overwrite that edit and retains its recovery journal.

An archive inspection or a green unit test is not a passed hardware/VM acceptance. Record command output, applied policy, reboot evidence and restoration checks before marking this phase accepted.
