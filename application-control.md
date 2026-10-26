# F3 — execution and network control

Approved continuation of roadmap-v2.md. Local checks never deploy App Control or firewall policies to the development host; enforcement acceptance requires a disposable Windows VM/Sandbox and explicit capability checks.

1. Add failing tests for execution selectors, safe paths, verified publishers, hash/sample matching, independent network rules and preserving unrelated policy; commit tests first.
2. Implement `applications.rs`: installed/running inventory with path, SHA-256 and verified Authenticode publisher; resolve execution selectors to a local representative and refuse missing/unverified samples.
3. Embed a bounded SYSTEM-only Windows adapter. Build an unsigned, removable App Control policy from the Windows AllowAll template plus deny rules. ConfigCI computes Authenticode hashes from validated samples; raw file SHA-256 must never be treated as a WDAC hash. Deny rules apply to user mode only; reject policies targeting core Windows/agent components or broad Microsoft publishers.
4. Deploy/update only the journaled openems policy GUID using CiTool; verify actual enforcement. CiTool needs Windows 11 22H2+/Server 2025. Unsupported OS and restart requirements are explicit failures without a successful ACK. Never remove or replace unrelated App Control policies.
5. Add owned outbound/inbound executable firewall blocks using exact paths; snapshot/write-ahead ownership and roll back failed updates. Policy release and uninstall remove only owned rules and policy.
6. Integrate inventory/events, UI and runtime. Keep existing `app_control.blocked` process termination as fallback, separate from proof of pre-execution blocking. Run full suites, then prepare physical acceptance: blocked hash and renamed copy never execute, publisher deny, network-only block while a control app connects, offline restart and baseline restoration.

Wire: `app_control:{blocked:[name],execution_rules:[{id,kind:hash|publisher|path|name,value,sample_path?:absolute}],network_blocked:[absolute_executable]}`. Publisher rules require a valid Authenticode signature; name rules use PE OriginalFileName metadata. A removed signed/locked policy may require reboot; never claim immediate removal without observing the OS state.

References: [CiTool](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/operations/citool-commands), [ConfigCI rules](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicyrule).
