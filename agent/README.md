# openems reference agent

A small, stdlib-only endpoint agent that enforces **server-defined web/app
blocks locally**, so the policy applies on **any network, with no VPN** — the
enforcement happens on the device, not through a tunnel.

- **Web filtering** → writes blocked domains into the OS **hosts file**
  (`0.0.0.0 domain`), enforced by the OS resolver everywhere.
- **App control** → **terminates** processes whose image name is blocked.

Policy comes from the server: the agent registers, then polls its **assigned
profile** (`/fct/api/public/v1/config/assigned/`), whose `body` carries:

```json
{
  "web_filter":  { "blocked": ["badsite.test", "ads.example.com"] },
  "app_control": { "blocked": ["someapp.exe"] }
}
```

Assignment rules on the server (e.g. "Windows endpoints → Strict") decide which
profile each endpoint gets, so you manage blocks centrally and they take effect
wherever the device is.

## Run

```bash
# safe test run: dry-run, and a throwaway hosts file
python openems_agent.py --server http://localhost:8013 --devid MY-PC-01 \
    --hosts-file ./test-hosts --dry-run

# real enforcement (needs admin/root to write the system hosts file and kill apps)
python openems_agent.py --server http://localhost:8013 --devid MY-PC-01
```

Flags: `--vdom`, `--interval <seconds>`, `--hosts-file <path>`, `--dry-run`.

## Run as a Windows service (boot-time, continuous)

From an **elevated / Administrator** PowerShell:
```powershell
.\install_service.ps1 -Server http://EMS_HOST:8013 -DevId MY-PC-01
```
This writes `C:\ProgramData\openems\agent.json`, installs **pywin32**, and
registers `openems-agent` as a **LocalSystem** service set to start at boot. It
runs the register → fetch-policy → enforce → report loop continuously. Logs:
`C:\ProgramData\openems\agent.log`. Remove with `.\uninstall_service.ps1`
(stops, removes, clears the hosts block).

## Security model (what "only bypassable with admin" means)

Running as a **LocalSystem service** gives the realistic tamper-resistance you
want: a **standard (non-admin) user cannot**
- stop/disable the service (service control needs admin),
- edit the hosts file (it is ACL-protected — admin only), or
- keep a blocked app alive (the SYSTEM service just re-terminates it).

So the blocks hold for ordinary users regardless of network, with no VPN.

> **Honest limit.** A local **administrator** (or SYSTEM) can always stop or
> remove any Windows service and edit any file — that is the OS trust model, and
> it is true of every endpoint agent, FortiClient included. "Unbypassable by a
> non-admin, only disableable by an admin" is the real, achievable guarantee.
> Going further (uninstall password, a kernel driver, early-launch protection)
> raises the bar but never makes it absolute against admin/SYSTEM.

## Telemetry

Each cycle the agent also reports posture **host tags** back to the server
(`os:…`, `vdom:…`, `app-control:clean|enforced`, `web-filter:N-blocked`) via
`POST /fct/api/public/v1/host_tags/`; they show up per-endpoint in the console
and can drive Zero-Trust-style assignment rules.

## How it was verified

`test_agent.py` covers the pure logic (hosts rendering, idempotent managed
block, process matching, dry-run). End-to-end: with the server running, a
profile blocking a site and a test app was published; the agent registered,
fetched its assigned profile, wrote the hosts block, and terminated the blocked
test process — all with a temp hosts file and a throwaway process, no real
system changes.

> This is a reference agent. Production-grade web/app control (preventing launch,
> deeper filtering, tamper resistance) needs an OS driver; the hosts-file +
> process-termination approach here is a portable, transparent baseline.
