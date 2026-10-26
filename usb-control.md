# F4 — removable USB storage

Approved continuation of roadmap-v2.md. Implementation and host verification never change real USB devices; destructive acceptance runs only in a disposable VM with USB passthrough. Windows Sandbox alone does not prove physical USB access.

1. Add failing tests for `usb_control` validation, ordered AND selectors, default action, keyboard/mouse immunity, inventory history and reversible changes; commit before implementation.
2. Implement `usb.rs`: normalized policy and inventory, first matching rule, deduplicated events, and a protected journal beside `state.json`.
3. Embed a bounded Windows PowerShell adapter. Inventory USB PnP nodes and USB disks; mutate only confirmed USB mass-storage child instances and non-boot/non-system disks. Preserve existing policy, PnP, offline and read-only state before changes; restore owned changes on policy release or removal.
4. Use per-instance installation restrictions and per-disk read-only/offline attributes; never disable a whole USB controller, hub, HID class or disk setup class. Conflicting external changes cause an explicit failure instead of overwriting administrator/GPO state.
5. Integrate runtime, authenticated inventory/events and panel through the shared contract. Empty policy is a no-op; active enforcement requires SYSTEM. Return errors for unsupported/partial application and pending restart, so the agent cannot ACK protection it did not apply.
6. Verify full native suites and harmless script parsing/planning locally. Prepare acceptance: blocked unknown USB, VID/PID/serial exception, failed write in read-only mode, keyboard/mouse unchanged, offline restart, policy release and uninstall restoring the baseline.

Wire: `usb_control:{default_action:allow|block|read_only,rules:[{id,action,class?:storage,vid?,pid?,serial?,instance_id?}]}`. Rules are ordered; selectors combine with AND. Input from policy and inventory is untrusted and bounded. A user-mode cycle can observe a new device after insertion; this is not a signed kernel filter or protection against a determined local administrator.

References: [device restrictions](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-deviceinstallation), [disk attributes](https://learn.microsoft.com/en-us/powershell/module/storage/set-disk).
