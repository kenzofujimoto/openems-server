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
