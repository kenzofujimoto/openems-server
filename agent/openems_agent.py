"""openems reference endpoint agent.

Enforces server-defined web/app blocks **locally on the endpoint**, so they
apply on any network with no VPN:

  * web filtering  -> writes blocked domains into the OS hosts file (resolve to
                      0.0.0.0), enforced by the OS resolver everywhere.
  * app control    -> terminates processes whose image name is blocked.

Policy comes from the server: the agent registers, then polls its assigned
profile (`/fct/api/public/v1/config/assigned/`). The profile `body` carries:

    {
      "web_filter":  {"blocked": ["example.com", "ads.example"]},
      "app_control": {"blocked": ["someapp.exe"]}
    }

Stdlib only (urllib / subprocess). Writing the system hosts file and killing
processes need admin/root; use --dry-run or --hosts-file to test safely.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable

HOSTS_BEGIN = "# >>> openems managed block >>>"
HOSTS_END = "# <<< openems managed block <<<"
_BLOCK_RE = re.compile(re.escape(HOSTS_BEGIN) + r".*?" + re.escape(HOSTS_END) + r"\n?", re.S)

DEFAULT_HOSTS = (
    r"C:\Windows\System32\drivers\etc\hosts" if os.name == "nt" else "/etc/hosts"
)


# --- pure helpers (unit-tested, no side effects) ------------------------

def render_hosts_block(domains: list[str]) -> str:
    """Render the managed hosts block for the blocked domains."""
    lines = [HOSTS_BEGIN]
    for d in domains:
        d = d.strip().lstrip("*.")
        if not d:
            continue
        lines.append(f"0.0.0.0 {d}")
        lines.append(f"0.0.0.0 www.{d}")
    lines.append(HOSTS_END)
    return "\n".join(lines) + "\n"


def replace_managed_block(current: str, block: str) -> str:
    """Swap our managed block in `current` for `block`, leaving the rest intact.

    Idempotent: re-applying the same policy yields the same file.
    """
    cleaned = _BLOCK_RE.sub("", current).rstrip("\n")
    if cleaned:
        cleaned += "\n"
    return cleaned + block


def processes_to_kill(running: list[str], blocked: list[str]) -> list[str]:
    """Which running image names match the blocked list (case-insensitive)."""
    wanted = {b.strip().lower() for b in blocked if b.strip()}
    seen: set[str] = set()
    out: list[str] = []
    for p in running:
        key = p.lower()
        if key in wanted and key not in seen:
            seen.add(key)
            out.append(p)
    return out


# --- side effects (enforcement) -----------------------------------------

def apply_hosts(domains: list[str], hosts_path: str) -> None:
    try:
        with open(hosts_path, encoding="utf-8", errors="replace") as fh:
            current = fh.read()
    except FileNotFoundError:
        current = ""
    with open(hosts_path, "w", encoding="utf-8") as fh:
        fh.write(replace_managed_block(current, render_hosts_block(domains)))


def clear_hosts(hosts_path: str) -> None:
    try:
        with open(hosts_path, encoding="utf-8", errors="replace") as fh:
            current = fh.read()
    except FileNotFoundError:
        return
    with open(hosts_path, "w", encoding="utf-8") as fh:
        fh.write(_BLOCK_RE.sub("", current))


def list_processes() -> list[str]:
    try:
        if os.name == "nt":
            out = subprocess.run(
                ["tasklist", "/fo", "csv", "/nh"], capture_output=True, text=True
            ).stdout
            return [ln.split('","')[0].strip('"') for ln in out.splitlines() if ln.strip()]
        out = subprocess.run(["ps", "-eo", "comm"], capture_output=True, text=True).stdout
        return [ln.strip() for ln in out.splitlines()[1:] if ln.strip()]
    except OSError:
        return []


def kill_process(name: str) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/f", "/im", name], capture_output=True)
    else:
        subprocess.run(["pkill", "-f", name], capture_output=True)


# --- agent --------------------------------------------------------------

@dataclass
class AgentConfig:
    server: str
    devid: str
    vdom: str = "Default"
    hosts_path: str = DEFAULT_HOSTS
    interval: int = 15
    dry_run: bool = False


def _api(url: str, data: dict | None = None):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(
        url, data=body, headers={"content-type": "application/json"},
        method="POST" if data is not None else "GET",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.load(resp)


def register(cfg: AgentConfig) -> str:
    r = _api(cfg.server + "/fct/api/public/v1/register/", {
        "devid": cfg.devid, "os": sys.platform,
        "hostname": os.environ.get("COMPUTERNAME") or os.uname().nodename
        if hasattr(os, "uname") else os.environ.get("COMPUTERNAME", "host"),
        "vdom": cfg.vdom,
    })
    return r["client_id"]


def fetch_profile(cfg: AgentConfig, client_id: str) -> dict | None:
    try:
        return _api(cfg.server + "/fct/api/public/v1/config/assigned/?client_id=" + client_id)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def enforce(cfg: AgentConfig, profile: dict | None, log: Callable[[str], None] = print) -> dict:
    body = (profile or {}).get("body", {})
    sites = list(body.get("web_filter", {}).get("blocked", []))
    apps = list(body.get("app_control", {}).get("blocked", []))

    if cfg.dry_run:
        log(f"[dry-run] would block {len(sites)} site(s) in {cfg.hosts_path}")
    else:
        apply_hosts(sites, cfg.hosts_path)
        log(f"web filter: {len(sites)} site(s) blocked via {cfg.hosts_path}")

    killed = processes_to_kill(list_processes(), apps)
    for name in killed:
        if cfg.dry_run:
            log(f"[dry-run] would terminate blocked app {name}")
        else:
            kill_process(name)
            log(f"app control: terminated blocked app {name}")
    return {"sites": sites, "killed": killed}


def compute_host_tags(cfg: AgentConfig, enforce_result: dict) -> list[str]:
    """Posture tags reported back to the server (feeds the EMS host-tag view)."""
    tags = [f"os:{sys.platform}", f"vdom:{cfg.vdom}"]
    tags.append("app-control:clean" if not enforce_result.get("killed") else "app-control:enforced")
    tags.append(f"web-filter:{len(enforce_result.get('sites', []))}-blocked")
    return tags


def report_host_tags(cfg: AgentConfig, client_id: str, tags: list[str]) -> None:
    try:
        _api(cfg.server + "/fct/api/public/v1/host_tags/", {"client_id": client_id, "tags": tags})
    except Exception:
        pass  # telemetry is best-effort


def run(cfg: AgentConfig, log: Callable[[str], None] = print) -> None:
    client_id = register(cfg)
    log(f"registered as client_id={client_id} (vdom={cfg.vdom})")
    while True:
        try:
            result = enforce(cfg, fetch_profile(cfg, client_id), log=log)
            report_host_tags(cfg, client_id, compute_host_tags(cfg, result))
        except Exception as e:  # keep the loop alive on transient errors
            log(f"loop error: {e}")
        time.sleep(cfg.interval)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="openems reference endpoint agent")
    ap.add_argument("--server", default="http://localhost:8013", help="EMS base URL")
    ap.add_argument("--devid", required=True, help="unique device id")
    ap.add_argument("--vdom", default="Default")
    ap.add_argument("--hosts-file", default=DEFAULT_HOSTS, dest="hosts_path",
                    help="hosts file to manage (use a temp path to test safely)")
    ap.add_argument("--interval", type=int, default=15)
    ap.add_argument("--dry-run", action="store_true", help="log actions, change nothing")
    args = ap.parse_args(argv)
    run(AgentConfig(server=args.server.rstrip("/"), devid=args.devid, vdom=args.vdom,
                    hosts_path=args.hosts_path, interval=args.interval, dry_run=args.dry_run))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
