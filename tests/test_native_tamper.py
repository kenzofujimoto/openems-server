"""Native agent tamper events against a disposable server; only a temporary hosts file is modified."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from app.events import InMemoryEventStore
from tests.test_agent_integration import live_server
from tests.test_native_agent import INVITATION
from tests.test_native_categories import stop, wait_for


def start(native: Path, origin: str, tmp_path: Path) -> subprocess.Popen:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("OPENEMS_")}
    environment["OPENEMS_INVITATION"] = INVITATION
    return subprocess.Popen(
        [str(native), "run", "--server", origin, "--devid", "tamper-pc", "--interval", "1",
         "--hosts-file", str(tmp_path / "hosts"), "--state-path", str(tmp_path / "state.json")],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=environment,
    )


def kinds(store: InMemoryEventStore) -> list[str]:
    return [event.kind for event in store.recent_tamper(50)]


def test_a_killed_agent_reports_its_unexpected_exit_after_restart(native, tmp_path):
    store = InMemoryEventStore()
    (tmp_path / "hosts").write_text("127.0.0.1 localhost\n", encoding="utf-8")
    with live_server(event_store=store) as (_, origin, client):
        assert client.post("/api/v1/profiles/Default", json={"web_filter": {"blocked": ["example.com"]}}).status_code == 200
        first = start(native, origin, tmp_path)
        try:
            assert wait_for(lambda: (tmp_path / "running.marker").exists(), 15), "run marker was not created"
            assert wait_for(lambda: "example.com" in (tmp_path / "hosts").read_text(encoding="utf-8"), 20)
        finally:
            first.kill()
            first.wait(timeout=15)
        assert "unexpected_exit" not in kinds(store), "a first start is not an unexpected exit"
        second = start(native, origin, tmp_path)
        try:
            if not wait_for(lambda: "unexpected_exit" in kinds(store), 20):
                raise AssertionError(f"unexpected exit not reported: {kinds(store)}\n" + stop(second))
            assert all(event.devid == "tamper-pc" for event in store.recent_tamper(50))
        finally:
            if second.poll() is None:
                stop(second)


def test_an_edited_managed_hosts_block_is_rewritten_and_reported(native, tmp_path):
    store = InMemoryEventStore()
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    with live_server(event_store=store) as (_, origin, client):
        assert client.post("/api/v1/profiles/Default", json={"web_filter": {"blocked": ["example.com"]}}).status_code == 200
        agent = start(native, origin, tmp_path)
        try:
            assert wait_for(lambda: "example.com" in hosts.read_text(encoding="utf-8"), 20)
            # Let at least one more cycle confirm the block before tampering with it.
            assert wait_for(lambda: (tmp_path / "state.json").exists(), 10)
            original = hosts.read_text(encoding="utf-8")
            hosts.write_text(original.replace("example.com", "example.invalid"), encoding="utf-8")
            if not wait_for(lambda: "hosts_restored" in kinds(store), 20):
                raise AssertionError(f"hosts edit not reported: {kinds(store)}\n" + stop(agent))
            assert "example.invalid" not in hosts.read_text(encoding="utf-8")
        finally:
            if agent.poll() is None:
                stop(agent)


def test_a_policy_change_is_not_reported_as_tampering(native, tmp_path):
    store = InMemoryEventStore()
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    with live_server(event_store=store) as (_, origin, client):
        assert client.post("/api/v1/profiles/Default", json={"web_filter": {"blocked": ["example.com"]}}).status_code == 200
        agent = start(native, origin, tmp_path)
        try:
            assert wait_for(lambda: "example.com" in hosts.read_text(encoding="utf-8"), 20)
            assert client.post("/api/v1/profiles/Default", json={"web_filter": {"blocked": ["example.org"]}}).status_code == 200
            assert wait_for(lambda: "example.org" in hosts.read_text(encoding="utf-8"), 20)
            time.sleep(3)  # give the agent time to upload anything it recorded
            assert "hosts_restored" not in kinds(store)
        finally:
            if agent.poll() is None:
                stop(agent)
