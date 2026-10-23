"""Endpoint safety and recovery tests; all OS writes use temporary files."""

import importlib
import json
import subprocess
import threading
import urllib.error

import openems_agent as a
import pytest


@pytest.mark.parametrize(
    "domain",
    [
        "*.com",
        "a.*.example.com",
        "https://example.com",
        "127.0.0.1",
        "bad.test\n1.2.3.4 injected.test",
        "bad test",
        "-bad.test",
    ],
)
def test_invalid_domain_never_changes_hosts(tmp_path, domain):
    hosts = tmp_path / "hosts"
    hosts.write_bytes(b"# original\r\n")
    with pytest.raises(ValueError):
        a.apply_hosts([domain], str(hosts))
    assert hosts.read_bytes() == b"# original\r\n"


@pytest.mark.parametrize(
    "body",
    [
        {"web_filter": {"blocked": "example.com"}},
        {"app_control": {"blocked": ["../app.exe"]}},
        {"app_control": {"blocked": ["-f"]}},
        {"web_filter": []},
        {"app_control": {"blocked": ["app.*"]}},
    ],
)
def test_policy_schema_rejects_unsafe_values(body):
    policy = importlib.import_module("agent.policy")
    with pytest.raises(ValueError):
        policy.validate_policy(body)


def test_policy_normalizes_domains_and_preserves_extensions():
    policy = importlib.import_module("agent.policy")
    value = policy.validate_policy(
        {
            "web_filter": {
                "blocked": ["EXAMPLE.COM", "example.com", "www.example.com", "täst.de"]
            },
            "firewall": "on",
        }
    )
    assert value["web_filter"]["blocked"] == [
        "example.com",
        "www.example.com",
        "xn--tst-qla.de",
    ]
    assert value["firewall"] == "on"
    assert "www.www.example.com" not in a.render_hosts_block(["www.example.com"])
    assert policy.policy_digest({"b": 2, "a": 1}) == policy.policy_digest(
        {"a": 1, "b": 2}
    )


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
    monkeypatch.setattr(
        a.os, "replace", lambda *args: (_ for _ in ()).throw(PermissionError("locked"))
    )
    with pytest.raises(PermissionError):
        a.apply_hosts(["example.com"], str(hosts))
    assert hosts.read_bytes() == b"# original\n"


def test_dns_failure_rolls_back_hosts(tmp_path, monkeypatch):
    hosts = tmp_path / "hosts"
    hosts.write_bytes(b"# original\n")
    monkeypatch.setattr(a, "DEFAULT_HOSTS", str(hosts))
    monkeypatch.setattr(
        a, "flush_dns", lambda: (_ for _ in ()).throw(RuntimeError("dns failure"))
    )
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
    monkeypatch.setattr(
        a,
        "_api",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            urllib.error.HTTPError("https://ems", 404, "unknown", {}, None)
        ),
    )
    with pytest.raises(urllib.error.HTTPError):
        a.fetch_profile(a.AgentConfig(server="https://ems", devid="pc"), "unknown")


def profile(vdom="Default", domain="example.com"):
    policy = importlib.import_module("agent.policy")
    body = {"web_filter": {"blocked": [domain]}}
    return {
        "vdom": vdom,
        "version": 1,
        "digest": policy.policy_digest(body),
        "body": body,
    }


def runtime(tmp_path, monkeypatch, api):
    monkeypatch.setattr(a, "_api", api)
    monkeypatch.setattr(a, "list_processes", list)
    cfg = a.AgentConfig(
        server="https://ems.test",
        devid="pc",
        hosts_path=str(tmp_path / "hosts"),
        state_path=str(tmp_path / "state.json"),
        interval=1,
    )
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
    assert ack[1] == {
        "client_id": "client",
        "vdom": "Default",
        "version": 1,
        "digest": assigned[0]["digest"],
        "success": True,
    }
    assert all(
        c[2].get("token") == "private-token"
        for c in calls
        if not c[0].endswith("/register/")
    )
    assigned[0] = profile("Strict", "other.test")
    engine.cycle(now=2)
    assert "other.test" in (tmp_path / "hosts").read_text()
    assert [c for c in calls if c[0].endswith("/config/ack/")][-1][1][
        "vdom"
    ] == "Strict"


def test_failed_enforcement_never_sends_success_ack(tmp_path, monkeypatch):
    calls = []
    engine = runtime(tmp_path, monkeypatch, fake_server([profile()], calls))
    monkeypatch.setattr(
        a, "apply_hosts", lambda *args: (_ for _ in ()).throw(PermissionError("denied"))
    )
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
    assigned[0] = {
        "vdom": "Default",
        "version": 0,
        "digest": "",
        "body": None,
        "unassigned": True,
    }
    engine.cycle(now=2)
    assert "example.com" not in (tmp_path / "hosts").read_text()


def test_runtime_rejects_plaintext_remote_endpoint(tmp_path):
    cfg = a.AgentConfig(
        server="http://remote.test:8013",
        devid="pc",
        state_path=str(tmp_path / "state.json"),
    )
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
    thread = threading.Thread(
        target=a.run,
        args=(engine.cfg,),
        kwargs={"stop_event": stop, "log": lambda message: None},
    )
    thread.start()
    try:
        assert network_entered.wait(1)
        assert local_enforced.wait(0.5), (
            "network request delayed cached local enforcement"
        )
    finally:
        stop.set()
        release_network.set()
        thread.join(3)
    assert not thread.is_alive()


def test_state_file_is_protected_before_credential_bytes_are_written(
    tmp_path, monkeypatch
):
    protected = []

    def secure_file(path):
        from pathlib import Path

        protected.append(Path(path).read_bytes())

    monkeypatch.setattr(a, "_secure_file", secure_file, raising=False)
    calls = []
    engine = runtime(tmp_path, monkeypatch, fake_server([profile()], calls))
    engine.cycle(now=0)
    assert protected and all(contents == b"" for contents in protected)


@pytest.mark.parametrize(
    "content",
    [
        a.HOSTS_END + "\n" + a.HOSTS_BEGIN + "\n",
        a.HOSTS_BEGIN + "\n",
        a.HOSTS_BEGIN
        + "\n"
        + a.HOSTS_END
        + "\n"
        + a.HOSTS_BEGIN
        + "\n"
        + a.HOSTS_END
        + "\n",
    ],
)
def test_malformed_managed_markers_never_acknowledge_a_hosts_write(tmp_path, content):
    hosts = tmp_path / "hosts"
    hosts.write_text(content)
    with pytest.raises(ValueError):
        a.apply_hosts(["example.com"], str(hosts))
    assert hosts.read_text() == content


def test_hosts_without_final_newline_restores_exact_original(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_bytes(b"# preserved without newline")
    a.apply_hosts(["example.com"], str(hosts))
    a.clear_hosts(str(hosts))
    assert hosts.read_bytes() == b"# preserved without newline"


@pytest.mark.parametrize(
    "server,interval,devid",
    [
        ("https://user:password@ems.test", 1, "pc"),
        ("https://ems.test/path", 1, "pc"),
        ("https://ems.test", 0, "pc"),
        ("https://ems.test", True, "pc"),
        ("https://ems.test", 1, ""),
    ],
)
def test_invalid_runtime_configuration_fails_before_io(
    tmp_path, server, interval, devid
):
    with pytest.raises(ValueError):
        a.AgentRuntime(
            a.AgentConfig(
                server=server,
                interval=interval,
                devid=devid,
                state_path=str(tmp_path / "state.json"),
            )
        )
    assert not (tmp_path / "state.json").exists()


@pytest.mark.parametrize(
    "state",
    [
        "not-json",
        json.dumps({"server": "https://other.test", "devid": "pc"}),
        json.dumps({"server": "https://ems.test", "devid": "pc", "client_id": []}),
    ],
)
def test_corrupt_or_foreign_cache_never_silently_resets_identity(tmp_path, state):
    cache = tmp_path / "state.json"
    cache.write_text(state)
    with pytest.raises(ValueError, match="cannot load"):
        a.AgentRuntime(
            a.AgentConfig(server="https://ems.test", devid="pc", state_path=str(cache))
        )
    assert cache.read_text() == state


@pytest.mark.parametrize(
    "assigned",
    [
        None,
        {"vdom": ""},
        {"vdom": "Default", "version": True},
        {
            "vdom": "Default",
            "version": 1,
            "digest": "",
            "body": None,
            "unassigned": True,
        },
    ],
)
def test_malformed_assignment_keeps_last_applied_policy(
    tmp_path, monkeypatch, assigned
):
    calls = []
    assignments = [profile()]
    engine = runtime(tmp_path, monkeypatch, fake_server(assignments, calls))
    engine.cycle(now=0)
    assignments[0] = assigned
    engine.cycle(now=2)
    assert "example.com" in (tmp_path / "hosts").read_text()
    assert json.loads((tmp_path / "state.json").read_text())["profile"]["body"][
        "web_filter"
    ]["blocked"] == ["example.com"]


def test_runtime_dry_run_never_writes_or_confirms_policy(tmp_path, monkeypatch):
    calls = []
    engine = runtime(tmp_path, monkeypatch, fake_server([profile()], calls))
    engine.cfg.dry_run = True
    engine.cycle(now=0)
    assert not (tmp_path / "state.json").exists()
    assert not (tmp_path / "hosts").exists()
    assert not any(c[0].endswith("/config/ack/") for c in calls)


def test_transient_failure_backs_off_without_repeating_registration(
    tmp_path, monkeypatch
):
    calls = []
    base = fake_server([profile()], calls)
    engine = runtime(tmp_path, monkeypatch, base)
    engine.cycle(now=0)

    def offline(url, *args, **kwargs):
        calls.append((url, args, kwargs))
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(a, "_api", offline)
    engine.cycle(now=2)
    count = len(calls)
    engine.cycle(now=2.01)
    assert len(calls) == count
    assert engine.client_id == "client"
    assert "example.com" in (tmp_path / "hosts").read_text()


def test_cli_reads_enrollment_secrets_from_environment(tmp_path, monkeypatch):
    observed = []
    monkeypatch.setenv("OPENEMS_INVITATION", "single-use")
    monkeypatch.setenv("OPENEMS_DEVICE_TOKEN", "device-secret")
    monkeypatch.setattr(a, "run", lambda cfg: observed.append(cfg))
    assert (
        a.main(["--devid", "pc", "--hosts-file", str(tmp_path / "hosts"), "--dry-run"])
        == 0
    )
    assert observed[0].invitation == "single-use"
    assert observed[0].device_token == "device-secret"


def test_api_sends_bearer_credentials_and_disables_redirects_and_proxy(monkeypatch):
    observed = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, limit):
            return b'{"ok":true}'

    class Opener:
        def open(self, request, timeout):
            observed.append(request)
            return Response()

    handlers = []

    def build(*values):
        handlers.extend(values)
        return Opener()

    monkeypatch.setattr(a.urllib.request, "build_opener", build)
    assert a._api("https://ems.test/", {"client_id": "client"}, token="private") == {
        "ok": True
    }
    assert observed[0].get_header("Authorization") == "Bearer private"
    assert observed[0].get_method() == "POST"
    assert handlers[0].proxies == {}
    with pytest.raises(urllib.error.HTTPError):
        handlers[1].redirect_request(
            observed[0], None, 302, "redirect", {}, "https://other.test"
        )


@pytest.mark.parametrize(
    "body",
    [
        None,
        {"extra": {1, 2}},
        {"web_filter": {"blocked": ["x.test"] * 10001}},
        {"app_control": {"blocked": ["app..exe"]}},
        {"app_control": {"blocked": ["app.exe "]}},
        {"web_filter": {"blocked": ["x\ud800.test"]}},
    ],
)
def test_policy_boundary_values_fail_explicitly(body):
    policy = importlib.import_module("agent.policy")
    with pytest.raises(ValueError):
        policy.validate_policy(body)


def test_block_page_bind_failure_is_visible_to_caller(monkeypatch):
    import blockpage

    def unavailable(port, bind="127.0.0.1"):
        raise OSError("port busy")

    monkeypatch.setattr(blockpage, "create_server", unavailable)
    with pytest.raises(OSError, match="port busy"):
        a.start_block_page(8123)


def test_agent_stop_closes_block_page_listener(tmp_path, monkeypatch):
    from unittest.mock import Mock

    page = Mock()
    monkeypatch.setattr(a, "start_block_page", lambda port: page)
    stop = threading.Event()
    stop.set()
    cfg = a.AgentConfig(
        server="https://ems.test",
        devid="pc",
        state_path=str(tmp_path / "state.json"),
        block_page=True,
    )
    a.run(cfg, stop_event=stop)
    page.shutdown.assert_called_once()
    page.server_close.assert_called_once()


def test_process_listing_and_exact_kill_commands_are_checked(monkeypatch):
    from types import SimpleNamespace

    calls = []

    def execute(command, **kwargs):
        calls.append((command, kwargs))
        output = (
            '"safe.exe","123","Console","1","4 K"\n'
            if command[0] == "tasklist"
            else "/usr/bin/safe\nother\n"
        )
        return subprocess.CompletedProcess(command, 0, stdout=output)

    monkeypatch.setattr(a.subprocess, "run", execute)
    monkeypatch.setattr(a, "os", SimpleNamespace(name="nt"))
    assert a.list_processes() == ["safe.exe"]
    a.kill_process("safe.exe")
    monkeypatch.setattr(a, "os", SimpleNamespace(name="posix"))
    assert a.list_processes() == ["safe", "other"]
    a.kill_process("safe")
    assert calls[-1][0] == ["pkill", "-x", "safe"]
    assert all(kwargs["check"] and kwargs["timeout"] == 15 for _, kwargs in calls)


def test_dns_flush_uses_platform_tools_and_surfaces_failure(monkeypatch):
    from types import SimpleNamespace

    calls = []
    monkeypatch.setattr(
        a.subprocess, "run", lambda command, **kwargs: calls.append((command, kwargs))
    )
    monkeypatch.setattr(a, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(a.platform, "system", lambda: "Darwin")
    a.flush_dns()
    monkeypatch.setattr(a.platform, "system", lambda: "Linux")
    monkeypatch.setattr(a.shutil, "which", lambda name: "/usr/bin/resolvectl")
    a.flush_dns()
    monkeypatch.setattr(a, "os", SimpleNamespace(name="nt"))
    a.flush_dns()
    assert [entry[0][0] for entry in calls] == ["dscacheutil", "resolvectl", "ipconfig"]
    assert all(kwargs["check"] for _, kwargs in calls)


def test_enforcement_reports_only_successful_process_termination(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(a, "list_processes", lambda: ["safe.exe", "other.exe"])
    monkeypatch.setattr(a, "kill_process", lambda name: calls.append(name))
    cfg = a.AgentConfig(
        server="https://ems.test", devid="pc", hosts_path=str(tmp_path / "hosts")
    )
    outcome = a.enforce(
        cfg,
        {"body": {"app_control": {"blocked": ["safe.exe"]}}},
        log=lambda message: None,
    )
    assert calls == outcome["killed"] == ["safe.exe"]


@pytest.mark.parametrize(
    "response", [{"client_id": "client"}, {"device_token": "token"}]
)
def test_registration_requires_credential_and_identity(monkeypatch, response):
    monkeypatch.setattr(a, "_api", lambda *args, **kwargs: response)
    with pytest.raises(ValueError):
        a.register(a.AgentConfig(server="https://ems.test", devid="pc"))


def test_registration_reuses_credential_without_server_reissuing_it(monkeypatch):
    payloads = []

    def api(url, data):
        payloads.append(data)
        return {"client_id": "renewed"}

    monkeypatch.setattr(a, "_api", api)
    cfg = a.AgentConfig(
        server="https://ems.test",
        devid="pc",
        device_token="existing",
        invitation="invite",
    )
    assert a.register(cfg) == "renewed"
    assert cfg.device_token == "existing"
    assert payloads[0]["key"] == "existing" and payloads[0]["invitation"] == "invite"


def test_api_rejects_oversized_reply(monkeypatch):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, limit):
            return b"x" * limit

    class Opener:
        def open(self, *args, **kwargs):
            return Response()

    monkeypatch.setattr(a.urllib.request, "build_opener", lambda *args: Opener())
    with pytest.raises(ValueError, match="size limit"):
        a._api("https://ems.test")


def test_runtime_404_preserves_block_and_recovers_with_existing_key(
    tmp_path, monkeypatch
):
    calls = []
    base = fake_server([profile()], calls)
    engine = runtime(tmp_path, monkeypatch, base)
    engine.cycle(now=0)

    def unknown(url, data=None, **kwargs):
        raise urllib.error.HTTPError(url, 404, "unknown", {}, None)

    monkeypatch.setattr(a, "_api", unknown)
    engine.cycle(now=2)
    assert engine.client_id is None
    assert "example.com" in (tmp_path / "hosts").read_text()
    monkeypatch.setattr(a, "_api", base)
    engine.cycle(now=100)
    assert [call for call in calls if call[0].endswith("/register/")][-1][1][
        "key"
    ] == "private-token"


def test_fatal_network_worker_is_not_hidden_by_running_local_loop(
    tmp_path, monkeypatch
):
    def fatal(*args):
        raise SystemExit("unexpected worker termination")

    monkeypatch.setattr(a.AgentRuntime, "_synchronize", fatal)
    cfg = a.AgentConfig(
        server="https://ems.test",
        devid="pc",
        state_path=str(tmp_path / "state.json"),
        interval=0.01,
    )
    with pytest.raises(RuntimeError, match="worker terminated"):
        a.run(cfg, log=lambda message: None)


def test_host_write_detects_concurrent_unmanaged_edit(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_bytes(b"new owner edit\n")
    with pytest.raises(RuntimeError, match="concurrently"):
        a._atomic_write(hosts, b"replacement", expected=b"old content\n")
    assert hosts.read_bytes() == b"new owner edit\n"


def test_invalid_render_target_or_broken_cleanup_markers_never_write(tmp_path):
    with pytest.raises(ValueError):
        a.render_hosts_block(["example.com"], "8.8.8.8")
    assert a.clear_hosts(str(tmp_path / "missing")) is False
    hosts = tmp_path / "hosts"
    hosts.write_text(a.HOSTS_BEGIN)
    with pytest.raises(ValueError):
        a.clear_hosts(str(hosts))
    assert hosts.read_text() == a.HOSTS_BEGIN
