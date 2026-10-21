"""Tests for the reference agent's enforcement logic (no real system changes)."""

from __future__ import annotations

import openems_agent as a


# --- hosts rendering ----------------------------------------------------

def test_render_hosts_block_has_markers_and_entries() -> None:
    block = a.render_hosts_block(["example.com", "*.ads.example"])
    assert a.HOSTS_BEGIN in block and a.HOSTS_END in block
    assert "0.0.0.0 example.com" in block
    assert "0.0.0.0 www.example.com" in block
    assert "0.0.0.0 ads.example" in block  # leading *. stripped


def test_replace_managed_block_preserves_other_content() -> None:
    current = "127.0.0.1 localhost\n"
    out = a.replace_managed_block(current, a.render_hosts_block(["bad.test"]))
    assert "127.0.0.1 localhost" in out
    assert "0.0.0.0 bad.test" in out


def test_replace_managed_block_is_idempotent() -> None:
    base = "127.0.0.1 localhost\n"
    once = a.replace_managed_block(base, a.render_hosts_block(["bad.test"]))
    twice = a.replace_managed_block(once, a.render_hosts_block(["bad.test"]))
    assert once == twice  # re-applying the same policy does not grow the file


def test_replace_managed_block_updates_policy() -> None:
    base = "127.0.0.1 localhost\n"
    first = a.replace_managed_block(base, a.render_hosts_block(["old.test"]))
    second = a.replace_managed_block(first, a.render_hosts_block(["new.test"]))
    assert "old.test" not in second
    assert "0.0.0.0 new.test" in second
    assert "127.0.0.1 localhost" in second


# --- hosts file I/O (temp file, never the system hosts) -----------------

def test_apply_and_clear_hosts(tmp_path) -> None:
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    a.apply_hosts(["bad.test"], str(hosts))
    assert "0.0.0.0 bad.test" in hosts.read_text(encoding="utf-8")
    a.clear_hosts(str(hosts))
    text = hosts.read_text(encoding="utf-8")
    assert "bad.test" not in text and "127.0.0.1 localhost" in text


# --- app matching -------------------------------------------------------

def test_processes_to_kill_case_insensitive_and_deduped() -> None:
    running = ["chrome.exe", "PING.EXE", "ping.exe", "notepad.exe"]
    assert a.processes_to_kill(running, ["ping.exe"]) == ["PING.EXE"]
    assert a.processes_to_kill(running, ["calc.exe"]) == []


# --- enforce (dry-run, stubbed process list) ----------------------------

def test_enforce_dry_run_reports_without_changes(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(a, "list_processes", lambda: ["ping.exe", "chrome.exe"])
    killed_calls = []
    monkeypatch.setattr(a, "kill_process", lambda n: killed_calls.append(n))

    cfg = a.AgentConfig(server="http://x", devid="d", hosts_path=str(tmp_path / "hosts"), dry_run=True)
    profile = {"body": {
        "web_filter": {"blocked": ["ads.test"]},
        "app_control": {"blocked": ["ping.exe"]},
    }}
    result = a.enforce(cfg, profile, log=lambda m: None)

    assert result["sites"] == ["ads.test"]
    assert result["killed"] == ["ping.exe"]
    assert killed_calls == []  # dry-run killed nothing
    assert not (tmp_path / "hosts").exists()  # dry-run wrote nothing


# --- telemetry / host tags ---------------------------------------------

def test_compute_host_tags() -> None:
    import sys

    cfg = a.AgentConfig(server="x", devid="d", vdom="Strict")
    tags = a.compute_host_tags(cfg, {"sites": ["x.test"], "killed": []})
    assert f"os:{sys.platform}" in tags
    assert "vdom:Strict" in tags
    assert "app-control:clean" in tags
    assert "web-filter:1-blocked" in tags
    assert "app-control:enforced" in a.compute_host_tags(cfg, {"sites": [], "killed": ["app.exe"]})


# --- service config loading --------------------------------------------

def test_service_load_config(tmp_path) -> None:
    import json

    import service

    cfg_file = tmp_path / "agent.json"
    cfg_file.write_text(
        json.dumps({"server": "http://x:8013/", "devid": "PC1",
                    "vdom": "Strict", "interval": 30}),
        encoding="utf-8",
    )
    cfg = service.load_config(str(cfg_file))
    assert cfg.server == "http://x:8013"  # trailing slash trimmed
    assert cfg.devid == "PC1" and cfg.vdom == "Strict" and cfg.interval == 30
