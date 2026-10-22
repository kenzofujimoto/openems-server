"""Endpoint safety and recovery tests; all OS writes use temporary files."""

import importlib
import json
import subprocess
import threading
import urllib.error

import pytest

import openems_agent as a


@pytest.mark.parametrize("domain", ["*.example.com", "https://example.com", "127.0.0.1", "bad.test\n1.2.3.4 injected.test", "bad test", "-bad.test"])
def test_invalid_domain_never_changes_hosts(tmp_path, domain):
    hosts = tmp_path / "hosts"
    hosts.write_bytes(b"# original\r\n")
    with pytest.raises(ValueError):
        a.apply_hosts([domain], str(hosts))
    assert hosts.read_bytes() == b"# original\r\n"


@pytest.mark.parametrize("body", [{"web_filter": {"blocked": "example.com"}}, {"app_control": {"blocked": ["../app.exe"]}}, {"app_control": {"blocked": ["-f"]}}, {"web_filter": []}, {"app_control": {"blocked": ["app.*"]}}])
def test_policy_schema_rejects_unsafe_values(body):
    policy = importlib.import_module("agent.policy")
    with pytest.raises(ValueError):
        policy.validate_policy(body)


def test_policy_normalizes_domains_and_preserves_extensions():
    policy = importlib.import_module("agent.policy")
    value = policy.validate_policy({"web_filter": {"blocked": ["EXAMPLE.COM", "example.com", "www.example.com", "täst.de"]}, "firewall": "on"})
    assert value["web_filter"]["blocked"] == ["example.com", "www.example.com", "xn--tst-qla.de"]
    assert value["firewall"] == "on"
    assert "www.www.example.com" not in a.render_hosts_block(["www.example.com"])
    assert policy.policy_digest({"b": 2, "a": 1}) == policy.policy_digest({"a": 1, "b": 2})


def test_hosts_preserves_bytes_creates_backup_and_skips_identical_write(tmp_path):
    hosts = tmp_path / "hosts"
    original = b"# custom\r\n127.0.0.1 localhost\r\n"
    hosts.write_bytes(original)
    assert a.apply_hosts(["example.com"], str(hosts)) is True
    assert hosts.read_bytes().startswith(original)
    assert (tmp_path / "hosts.openems.bak").read_bytes() == original
    stamp = hosts.stat().st_mtime_ns
    assert a.apply_hosts(["example.com"], str(hosts)) is False
    assert hosts.stat().st_mtime_ns == stamp
    a.clear_hosts(str(hosts))
    assert hosts.read_bytes() == original


def test_replace_failure_preserves_original(tmp_path, monkeypatch):
    hosts = tmp_path / "hosts"
    hosts.write_bytes(b"# original\n")
    monkeypatch.setattr(a.os, "replace", lambda *args: (_ for _ in ()).throw(PermissionError("locked")))
    with pytest.raises(PermissionError):
        a.apply_hosts(["example.com"], str(hosts))
    assert hosts.read_bytes() == b"# original\n"


def test_dns_failure_rolls_back_hosts(tmp_path, monkeypatch):
    hosts = tmp_path / "hosts"
    hosts.write_bytes(b"# original\n")
    monkeypatch.setattr(a, "DEFAULT_HOSTS", str(hosts))
    monkeypatch.setattr(a, "flush_dns", lambda: (_ for _ in ()).throw(RuntimeError("dns failure")))
    with pytest.raises(RuntimeError, match="dns failure"):
        a.apply_hosts(["example.com"], str(hosts))
    assert hosts.read_bytes() == b"# original\n"


def test_process_command_failure_is_not_reported_as_success(monkeypatch):
    def failed(*args, **kwargs):
        if kwargs.get("check"):
            raise subprocess.CalledProcessError(5, args[0])
        return subprocess.CompletedProcess(args[0], 5, stdout="", stderr="denied")
    monkeypatch.setattr(a.subprocess, "run", failed)
    with pytest.raises((subprocess.CalledProcessError, RuntimeError)):
        a.kill_process("disposable.exe")


def test_unknown_endpoint_404_is_not_policy_release(monkeypatch):
    monkeypatch.setattr(a, "_api", lambda *args, **kwargs: (_ for _ in ()).throw(urllib.error.HTTPError("https://ems", 404, "unknown", {}, None)))
    with pytest.raises(urllib.error.HTTPError):
        a.fetch_profile(a.AgentConfig(server="https://ems", devid="pc"), "unknown")


def profile(vdom="Default", domain="example.com"):
    policy = importlib.import_module("agent.policy")
    body = {"web_filter": {"blocked": [domain]}}
    return {"vdom": vdom, "version": 1, "digest": policy.policy_digest(body), "body": body}


def runtime(tmp_path, monkeypatch, api):
    monkeypatch.setattr(a, "_api", api)
    monkeypatch.setattr(a, "list_processes", lambda: [])
    cfg = a.AgentConfig(server="https://ems.test", devid="pc", hosts_path=str(tmp_path / "hosts"), state_path=str(tmp_path / "state.json"), interval=1)
    return a.AgentRuntime(cfg, log=lambda message: None)


def fake_server(assigned, calls):
    def api(url, data=None, **kwargs):
        calls.append((url, data, kwargs))
        if url.endswith("/register/"):
            return {"client_id": "client", "device_token": "private-token"}
        if "/config/assigned/" in url:
            return assigned[0]
        return {"messages": []}
    return api


def test_success_ack_has_full_assignment_identity_and_auth(tmp_path, monkeypatch):
    calls = []
    assigned = [profile()]
    engine = runtime(tmp_path, monkeypatch, fake_server(assigned, calls))
    engine.cycle(now=0)
    ack = [c for c in calls if c[0].endswith("/config/ack/")][-1]
    assert ack[1] == {"client_id": "client", "vdom": "Default", "version": 1, "digest": assigned[0]["digest"], "success": True}
    assert all(c[2].get("token") == "private-token" for c in calls if not c[0].endswith("/register/"))
    assigned[0] = profile("Strict", "other.test")
    engine.cycle(now=2)
    assert "other.test" in (tmp_path / "hosts").read_text()
    assert [c for c in calls if c[0].endswith("/config/ack/")][-1][1]["vdom"] == "Strict"


def test_failed_enforcement_never_sends_success_ack(tmp_path, monkeypatch):
    calls = []
    engine = runtime(tmp_path, monkeypatch, fake_server([profile()], calls))
    monkeypatch.setattr(a, "apply_hosts", lambda *args: (_ for _ in ()).throw(PermissionError("denied")))
    engine.cycle(now=0)
    acks = [c[1] for c in calls if c[0].endswith("/config/ack/")]
    assert acks and all(c["success"] is False for c in acks)


def test_offline_restart_uses_cached_policy_and_identity(tmp_path, monkeypatch):
    calls = []
    engine = runtime(tmp_path, monkeypatch, fake_server([profile()], calls))
    engine.cycle(now=0)
    state = json.loads((tmp_path / "state.json").read_text())
    assert state["device_token"] == "private-token"
    (tmp_path / "hosts").unlink()
    attempts = []
    def offline(url, *args, **kwargs):
        attempts.append(url)
        raise urllib.error.URLError("offline")
    restored = runtime(tmp_path, monkeypatch, offline)
    restored.cycle(now=10)
    assert "example.com" in (tmp_path / "hosts").read_text()
    assert restored.client_id == "client"
    assert all(not url.endswith("/register/") for url in attempts)


def test_explicit_unassignment_releases_cached_block(tmp_path, monkeypatch):
    calls = []
    assigned = [profile()]
    engine = runtime(tmp_path, monkeypatch, fake_server(assigned, calls))
    engine.cycle(now=0)
    assigned[0] = {"vdom": "Default", "version": 0, "digest": "", "body": None, "unassigned": True}
    engine.cycle(now=2)
    assert "example.com" not in (tmp_path / "hosts").read_text()


def test_runtime_rejects_plaintext_remote_endpoint(tmp_path):
    cfg = a.AgentConfig(server="http://remote.test:8013", devid="pc", state_path=str(tmp_path / "state.json"))
    with pytest.raises(ValueError, match="HTTPS"):
        a.AgentRuntime(cfg)


def test_lost_ack_is_retried_without_reapplying_new_version(tmp_path, monkeypatch):
    calls = []
    base = fake_server([profile()], calls)
    failures = [True]
    def api(url, data=None, **kwargs):
        if url.endswith("/config/ack/") and failures:
            failures.pop()
            calls.append((url, data, kwargs))
            raise urllib.error.URLError("lost ack")
        return base(url, data, **kwargs)
    engine = runtime(tmp_path, monkeypatch, api)
    engine.cycle(now=0)
    engine.cycle(now=100)
    assert len([c for c in calls if c[0].endswith("/config/ack/")]) == 2


def test_invalid_digest_keeps_previous_policy(tmp_path, monkeypatch):
    calls = []
    assigned = [profile()]
    engine = runtime(tmp_path, monkeypatch, fake_server(assigned, calls))
    engine.cycle(now=0)
    assigned[0] = {**profile("Strict", "other.test"), "digest": "0" * 64}
    engine.cycle(now=2)
    assert "example.com" in (tmp_path / "hosts").read_text()
    assert "other.test" not in (tmp_path / "hosts").read_text()


def test_no_profile_argument_never_releases_block(tmp_path):
    hosts = tmp_path / "hosts"
    a.apply_hosts(["example.com"], str(hosts))
    cfg = a.AgentConfig(server="https://ems", devid="pc", hosts_path=str(hosts))
    a.enforce(cfg, None, log=lambda message: None)
    assert "example.com" in hosts.read_text()


def test_running_agent_enforces_cache_while_network_is_blocked(tmp_path, monkeypatch):
    calls = []
    engine = runtime(tmp_path, monkeypatch, fake_server([profile()], calls))
    engine.cycle(now=0)
    stop = threading.Event()
    network_entered = threading.Event()
    release_network = threading.Event()
    def blocked_network(*args, **kwargs):
        network_entered.set()
        release_network.wait(2)
        raise urllib.error.URLError("offline")
    monkeypatch.setattr(a, "_api", blocked_network)
    original_enforce = a.enforce
    local_enforced = threading.Event()
    def observe_enforcement(*args, **kwargs):
        local_enforced.set()
        stop.set()
        return original_enforce(*args, **kwargs)
    monkeypatch.setattr(a, "enforce", observe_enforcement)
    thread = threading.Thread(target=a.run, args=(engine.cfg,), kwargs={"stop_event": stop, "log": lambda message: None})
    thread.start()
    try:
        assert network_entered.wait(1)
        assert local_enforced.wait(.5), "network request delayed cached local enforcement"
    finally:
        stop.set()
        release_network.set()
        thread.join(3)
    assert not thread.is_alive()


def test_state_file_is_protected_before_credential_bytes_are_written(tmp_path, monkeypatch):
    protected = []
    def secure_file(path):
        from pathlib import Path
        protected.append(Path(path).read_bytes())
    monkeypatch.setattr(a, "_secure_file", secure_file, raising=False)
    calls = []
    engine = runtime(tmp_path, monkeypatch, fake_server([profile()], calls))
    engine.cycle(now=0)
    assert protected and all(contents == b"" for contents in protected)
