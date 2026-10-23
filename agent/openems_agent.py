"""Authenticated endpoint synchronization with independent offline enforcement.

Hosts filtering covers exact names and www aliases. Process control terminates
exact executable names periodically; it does not prevent process launches.
"""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import os
import platform
import random
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from .policy import (
        hosts_names,
        normalize_process,
        policy_digest,
        validate_policy,
    )
except ImportError:
    from policy import (
        hosts_names,
        normalize_process,
        policy_digest,
        validate_policy,
    )

HOSTS_BEGIN = "# >>> openems managed block >>>"
HOSTS_END = "# <<< openems managed block <<<"
_BLOCK_RE = re.compile(
    re.escape(HOSTS_BEGIN) + r".*?" + re.escape(HOSTS_END) + r"\r?\n?", re.DOTALL
)
DEFAULT_HOSTS = (
    r"C:\Windows\System32\drivers\etc\hosts" if os.name == "nt" else "/etc/hosts"
)
DEFAULT_STATE = (
    str(
        Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
        / "openems"
        / "state.json"
    )
    if os.name == "nt"
    else "/var/lib/openems/state.json"
)


def render_hosts_block(
    domains: list[str], ip: str = "0.0.0.0", allowed: list[str] | tuple[str, ...] = ()
) -> str:
    if ip not in ("0.0.0.0", "127.0.0.1"):
        raise ValueError("unsupported hosts target")
    names = hosts_names(domains, list(allowed))
    return (
        "\n".join([HOSTS_BEGIN, *(f"{ip} {name}" for name in names), HOSTS_END]) + "\n"
    )


def replace_managed_block(current: str, block: str) -> str:
    if (
        current.count(HOSTS_BEGIN) != current.count(HOSTS_END)
        or current.count(HOSTS_BEGIN) > 1
    ):
        raise ValueError("hosts contains malformed managed markers")
    if HOSTS_BEGIN in current:
        if _BLOCK_RE.search(current) is None:
            raise ValueError("hosts contains reversed managed markers")
        return _BLOCK_RE.sub(lambda match: block, current, count=1)
    return current + ("\n" if current and not current.endswith("\n") else "") + block


def _secure_file(path: str) -> None:
    """Protect secret files before their first write, including on Windows."""
    if os.name != "nt":
        os.chmod(path, 0o600)
        return
    import ctypes
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG),
    ]
    advapi.SetFileSecurityW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    descriptor = ctypes.c_void_p()
    # OWNER RIGHTS permits the file creator; SYSTEM and Administrators cover
    # the service and recovery tools. Protected DACL prevents broad inheritance.
    sddl = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)"
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not advapi.SetFileSecurityW(path, 0x80000004, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.LocalFree(descriptor)


def _atomic_write(
    path: Path, data: bytes, *, expected: bytes | None = None, private: bool = False
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".openems-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            if private:
                _secure_file(temp)
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if path.exists() and not private:
            shutil.copymode(path, temp)
        else:
            os.chmod(temp, 0o600)
        if (
            expected is not None
            and (path.read_bytes() if path.exists() else b"") != expected
        ):
            raise RuntimeError("file changed concurrently; retry required")
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def flush_dns() -> None:
    if os.name == "nt":
        subprocess.run(
            ["ipconfig", "/flushdns"], capture_output=True, timeout=15, check=True
        )
    elif platform.system() == "Darwin":
        subprocess.run(
            ["dscacheutil", "-flushcache"], capture_output=True, timeout=15, check=True
        )
    elif shutil.which("resolvectl"):
        subprocess.run(
            ["resolvectl", "flush-caches"], capture_output=True, timeout=15, check=True
        )


def _write_hosts(path: Path, previous: bytes, updated: bytes) -> bool:
    if previous == updated:
        return False
    backup = path.with_name(path.name + ".openems.bak")
    try:
        with backup.open("xb") as fh:
            fh.write(previous)
    except FileExistsError:
        pass
    _atomic_write(path, updated, expected=previous)
    if path.resolve() == Path(DEFAULT_HOSTS).resolve():
        try:
            flush_dns()
        except Exception:
            _atomic_write(path, previous, expected=updated)
            raise
    return True


def apply_hosts(
    domains: list[str],
    hosts_path: str,
    ip: str = "0.0.0.0",
    allowed: list[str] | tuple[str, ...] = (),
) -> bool:
    block = render_hosts_block(domains, ip, allowed)
    path = Path(hosts_path)
    previous = path.read_bytes() if path.exists() else b""
    updated = replace_managed_block(
        previous.decode("utf-8", errors="surrogateescape"), block
    ).encode("utf-8", errors="surrogateescape")
    return _write_hosts(path, previous, updated)


def clear_hosts(hosts_path: str) -> bool:
    path = Path(hosts_path)
    if not path.exists():
        return False
    previous = path.read_bytes()
    text = previous.decode("utf-8", errors="surrogateescape")
    if (
        text.count(HOSTS_BEGIN) != text.count(HOSTS_END)
        or text.count(HOSTS_BEGIN) > 1
        or (HOSTS_BEGIN in text and _BLOCK_RE.search(text) is None)
    ):
        raise ValueError("hosts contains malformed managed markers")
    updated = _BLOCK_RE.sub("", text).encode("utf-8", errors="surrogateescape")
    backup = path.with_name(path.name + ".openems.bak")
    if backup.exists():
        original = backup.read_bytes()
        # Remove a separator we added only when the entire unmanaged content
        # still exactly matches the backup; never erase another editor's work.
        if original and not original.endswith(b"\n") and updated == original + b"\n":
            updated = original
    return _write_hosts(path, previous, updated)


def processes_to_kill(running: list[str], blocked: list[str]) -> list[str]:
    wanted = {normalize_process(name) for name in blocked}
    seen: set[str] = set()
    out = []
    for name in running:
        if name.lower() in wanted and name.lower() not in seen:
            seen.add(name.lower())
            out.append(name)
    return out


def list_processes() -> list[str]:
    command = (
        ["tasklist", "/fo", "csv", "/nh"] if os.name == "nt" else ["ps", "-eo", "comm="]
    )
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=15, check=True
    )
    if os.name == "nt":
        return [
            row[0] for row in csv.reader(io.StringIO(result.stdout)) if row and row[0]
        ]
    return [
        line.strip().rsplit("/", 1)[-1]
        for line in result.stdout.splitlines()
        if line.strip()
    ]


def kill_process(name: str) -> None:
    normalize_process(name)
    command = (
        ["taskkill", "/f", "/im", name]
        if os.name == "nt"
        else ["pkill", "-x", re.escape(name)]
    )
    subprocess.run(command, capture_output=True, timeout=15, check=True)


@dataclass
class AgentConfig:
    server: str
    devid: str
    vdom: str = "Default"
    hosts_path: str = DEFAULT_HOSTS
    interval: int = 15
    dry_run: bool = False
    block_page: bool = False
    block_page_port: int = 80
    invitation: str | None = None
    device_token: str | None = None
    state_path: str | None = None
    allow_insecure_http: bool = False


def start_block_page(port: int = 80):
    try:
        from .blockpage import create_server
    except ImportError:
        from blockpage import create_server
    server = create_server(port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    try:
        thread.start()
    except BaseException:
        server.server_close()
        raise
    return server


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "endpoint redirects are disabled", headers, fp
        )


def _api(url: str, data: dict | None = None, *, token: str | None = None):
    body = json.dumps(data).encode() if data is not None else None
    headers = {"content-type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(
        url, data=body, headers=headers, method="POST" if data is not None else "GET"
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    with opener.open(request, timeout=10) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("endpoint response exceeds size limit")
        return json.loads(raw)


def register(cfg: AgentConfig) -> str:
    payload: dict[str, Any] = {
        "devid": cfg.devid,
        "os": sys.platform,
        "hostname": platform.node(),
        "vdom": cfg.vdom,
    }
    if cfg.invitation:
        payload["invitation"] = cfg.invitation
    if cfg.device_token:
        payload["key"] = cfg.device_token
    result = _api(cfg.server + "/fct/api/public/v1/register/", payload)
    token = result.get("device_token") or cfg.device_token
    if not isinstance(token, str) or not token:
        raise ValueError("registration returned no device credential")
    if not isinstance(result.get("client_id"), str) or not result["client_id"]:
        raise ValueError("registration returned no client identity")
    cfg.device_token = token
    return result["client_id"]


def fetch_profile(cfg: AgentConfig, client_id: str) -> dict:
    return _api(
        cfg.server
        + "/fct/api/public/v1/config/assigned/?"
        + urllib.parse.urlencode({"client_id": client_id}),
        token=cfg.device_token,
    )


def enforce(
    cfg: AgentConfig, profile: dict | None, log: Callable[[str], None] = print
) -> dict:
    if profile is None:
        return {"sites": [], "killed": []}
    release = profile.get("unassigned") is True and profile.get("body") is None
    body = validate_policy({} if release else profile.get("body"))
    sites = body.get("web_filter", {}).get("blocked", [])
    allowed = body.get("web_filter", {}).get("allowed", [])
    apps = body.get("app_control", {}).get("blocked", [])
    if cfg.dry_run:
        log(
            f"[dry-run] would apply {len(sites)} domain block(s) and {len(apps)} process rule(s)"
        )
    elif release:
        clear_hosts(cfg.hosts_path)
    else:
        apply_hosts(
            sites, cfg.hosts_path, "127.0.0.1" if cfg.block_page else "0.0.0.0", allowed
        )
    killed = processes_to_kill(list_processes(), apps) if apps else []
    for name in killed:
        if not cfg.dry_run:
            kill_process(name)
        log(("[dry-run] would terminate " if cfg.dry_run else "terminated ") + name)
    return {"sites": sites, "killed": killed}


def compute_host_tags(cfg: AgentConfig, enforce_result: dict) -> list[str]:
    return [
        f"os:{sys.platform}",
        f"vdom:{cfg.vdom}",
        "app-control:enforced" if enforce_result.get("killed") else "app-control:clean",
        f"web-filter:{len(enforce_result.get('sites', []))}-blocked",
    ]


def report_host_tags(cfg: AgentConfig, client_id: str, tags: list[str]) -> None:
    _api(
        cfg.server + "/fct/api/public/v1/host_tags/",
        {"client_id": client_id, "tags": tags},
        token=cfg.device_token,
    )


def _validate_server(cfg: AgentConfig) -> None:
    parsed = urllib.parse.urlsplit(cfg.server)
    if (
        parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not parsed.hostname
        or parsed.path not in ("", "/")
    ):
        raise ValueError("server must be an origin without credentials, query or path")
    try:
        loopback = (
            parsed.hostname == "localhost"
            or ipaddress.ip_address(parsed.hostname).is_loopback
        )
    except ValueError:
        loopback = parsed.hostname == "localhost"
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and (loopback or cfg.allow_insecure_http)
    ):
        raise ValueError("HTTPS is required for remote endpoint connections")
    if (
        isinstance(cfg.interval, bool)
        or not isinstance(cfg.interval, (int, float))
        or cfg.interval <= 0
    ):
        raise ValueError("interval must be positive")
    if not cfg.devid:
        raise ValueError("devid is required")
    cfg.server = cfg.server.rstrip("/")


def _validated_profile(value: object) -> dict:
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("vdom"), str)
        or not value["vdom"]
    ):
        raise ValueError("invalid assignment identity")
    version = value.get("version")
    if isinstance(version, bool) or not isinstance(version, int):
        raise ValueError("invalid assignment version")  # noqa: TRY004 - invalid wire schema
    if value.get("unassigned") is True:
        if version != 0 or value.get("body") is not None or value.get("digest") != "":
            raise ValueError("invalid policy release")
    else:
        body = value.get("body")
        if (
            version <= 0
            or not isinstance(body, dict)
            or value.get("digest") != policy_digest(body)
        ):
            raise ValueError("policy integrity check failed")
        validate_policy(body)
    return value


def _identity(profile: dict) -> tuple[str, int, str]:
    return profile["vdom"], profile["version"], profile["digest"]


class AgentRuntime:
    """One local enforcement loop; synchronization retries never disable policy."""

    def __init__(self, cfg: AgentConfig, log: Callable[[str], None] = print):
        _validate_server(cfg)
        self.cfg, self.log = cfg, log
        self.client_id: str | None = None
        self.profile: dict | None = None
        self.last_ack: tuple[str, int, str] | None = None
        self.next_sync = 0.0
        self.failures = 0
        self.state_path = Path(cfg.state_path or DEFAULT_STATE)
        self._lock = threading.RLock()
        self._pending_status: dict | None = None
        self._stop_event: threading.Event | None = None
        if self.state_path.exists():
            try:
                state = json.loads(self.state_path.read_text(encoding="utf-8-sig"))
                if state.get("server") != cfg.server or state.get("devid") != cfg.devid:
                    raise ValueError(
                        "cached state belongs to another endpoint or server"
                    )
                cached = state.get("profile")
                self.profile = (
                    _validated_profile(cached) if cached is not None else None
                )
                self.client_id = state.get("client_id")
                cfg.device_token = state.get("device_token") or cfg.device_token
                if not isinstance(self.client_id, (str, type(None))) or not isinstance(
                    cfg.device_token, (str, type(None))
                ):
                    raise TypeError("invalid cached device credentials")
            except (ValueError, OSError, TypeError) as exc:
                raise ValueError(
                    "cannot load endpoint state; preserve hosts and repair state"
                ) from exc
        self._cached_profile = self.profile

    def _save(self) -> None:
        if self.cfg.dry_run:
            return
        with self._lock:
            state = {
                "server": self.cfg.server,
                "devid": self.cfg.devid,
                "client_id": self.client_id,
                "device_token": self.cfg.device_token,
                "profile": self._cached_profile,
            }
            _atomic_write(
                self.state_path,
                json.dumps(state, ensure_ascii=False).encode(),
                private=True,
            )

    def _post(self, path: str, payload: dict) -> dict:
        if self._stop_event is not None and self._stop_event.is_set():
            raise InterruptedError("agent stopping")
        return _api(
            self.cfg.server + "/fct/api/public/v1/" + path + "/",
            payload,
            token=self.cfg.device_token,
        )

    def _report_pending(self) -> None:
        if self.cfg.dry_run:
            return
        with self._lock:
            status = self._pending_status
        if status is None or self.client_id is None:
            return
        profile, success = status["profile"], status["success"]
        try:
            if not success or self.last_ack != _identity(profile):
                payload = {
                    "client_id": self.client_id,
                    "vdom": profile["vdom"],
                    "version": profile["version"],
                    "digest": profile["digest"],
                    "success": success,
                }
                if not success:
                    payload["error"] = status["error"]
                self._post("config/ack", payload)
                with self._lock:
                    self.last_ack = _identity(profile) if success else None
            if success:
                tags = compute_host_tags(self.cfg, status["result"])
                tags = [tag for tag in tags if not tag.startswith("vdom:")] + [
                    f"vdom:{profile['vdom']}"
                ]
                report_host_tags(self.cfg, self.client_id, tags)
            with self._lock:
                if self._pending_status is status:
                    self._pending_status = None
        except (OSError, ValueError, RuntimeError) as exc:
            self.log(
                f"policy status report failed ({type(exc).__name__}); retry next synchronization"
            )

    def _synchronize(self, now: float) -> bool:
        if now < self.next_sync:
            return False
        try:
            if self.client_id is None:
                client_id = register(self.cfg)
                if self._stop_event is not None and self._stop_event.is_set():
                    return False
                with self._lock:
                    self.client_id = client_id
                    self.last_ack = None
                    self._save()
            self._post("messages/pull", {"client_id": self.client_id})
            self._post("refresh", {"client_id": self.client_id})
            assignment = _validated_profile(fetch_profile(self.cfg, self.client_id))
            if self._stop_event is not None and self._stop_event.is_set():
                return False
            with self._lock:
                self.profile = assignment
                self.failures = 0
                self.next_sync = now + self.cfg.interval
            return True
        except (OSError, ValueError, RuntimeError) as exc:
            with self._lock:
                self.failures += 1
                self.next_sync = now + min(
                    300, self.cfg.interval * 2 ** min(self.failures, 8)
                ) * random.uniform(0.8, 1.2)
                if isinstance(exc, urllib.error.HTTPError) and exc.code == 404:
                    self.client_id = None
            self.log(
                f"synchronization failed ({type(exc).__name__}); cached enforcement continues"
            )
            return False

    def _enforce_local(self) -> None:
        with self._lock:
            profile = self.profile
        if profile is None:
            return
        try:
            result = enforce(self.cfg, profile, self.log)
            with self._lock:
                self._cached_profile = profile
                self._save()
                self._pending_status = {
                    "profile": profile,
                    "success": True,
                    "result": result,
                }
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            self.log(f"policy enforcement failed ({type(exc).__name__})")
            with self._lock:
                self._pending_status = {
                    "profile": profile,
                    "success": False,
                    "error": f"enforcement failed: {type(exc).__name__}",
                }
                self.last_ack = None

    def cycle(self, now: float | None = None) -> None:
        """Synchronous single-cycle entry point for diagnostics and tests."""
        now = time.monotonic() if now is None else now
        connected = self._synchronize(now)
        self._enforce_local()
        if connected:
            self._report_pending()


def run(
    cfg: AgentConfig,
    log: Callable[[str], None] = print,
    stop_event: threading.Event | None = None,
) -> None:
    stop = stop_event if stop_event is not None else threading.Event()
    runtime = AgentRuntime(cfg, log)
    runtime._stop_event = stop
    block_server = start_block_page(cfg.block_page_port) if cfg.block_page else None
    worker_errors: list[BaseException] = []

    def sync_worker():
        try:
            while not stop.is_set():
                if runtime._synchronize(time.monotonic()):
                    runtime._report_pending()
                stop.wait(min(cfg.interval, 1))
        except BaseException as exc:  # noqa: BLE001 - transfer fatal thread errors to main
            worker_errors.append(exc)
            stop.set()

    worker = threading.Thread(target=sync_worker, name="openems-sync", daemon=True)
    worker.start()
    try:
        while not stop.is_set():
            runtime._enforce_local()
            stop.wait(cfg.interval)
    finally:
        stop.set()
        worker.join(timeout=0.2)
        if block_server is not None:
            block_server.shutdown()
            block_server.server_close()
    if worker_errors:
        raise RuntimeError(
            "endpoint synchronization worker terminated"
        ) from worker_errors[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="openems endpoint agent")
    parser.add_argument("--server", default="http://localhost:8013")
    parser.add_argument("--devid", required=True)
    parser.add_argument("--vdom", default="Default")
    parser.add_argument("--hosts-file", default=DEFAULT_HOSTS, dest="hosts_path")
    parser.add_argument("--state-path", default=DEFAULT_STATE)
    parser.add_argument("--interval", type=int, default=15)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--block-page", action="store_true")
    parser.add_argument("--block-page-port", type=int, default=80)
    parser.add_argument("--allow-insecure-http", action="store_true")
    args = parser.parse_args(argv)
    run(
        AgentConfig(
            **vars(args),
            invitation=os.environ.get("OPENEMS_INVITATION"),
            device_token=os.environ.get("OPENEMS_DEVICE_TOKEN"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
