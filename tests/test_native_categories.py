"""Native agent with web categories against a disposable server, on an ephemeral DNS port only."""

from __future__ import annotations

import os
import socket
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

from app.categories import build_categories
from tests.test_agent_integration import live_server
from tests.test_native_agent import INVITATION
from tests.test_native_dns_cli import dns_query, free_port


def ut1(tmp_path: Path) -> Path:
    source = tmp_path / "blacklists"
    (source / "games").mkdir(parents=True)
    (source / "games" / "domains").write_text("steampowered.com\nsteamcommunity.com\n", encoding="utf-8")
    return source


def start_agent(native: Path, origin: str, tmp_path: Path, port: int) -> subprocess.Popen:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("OPENEMS_")}
    environment["OPENEMS_INVITATION"] = INVITATION
    return subprocess.Popen(
        [str(native), "run", "--server", origin, "--devid", "category-pc", "--interval", "1", "--dns-filter",
         "--dns-port", str(port), "--hosts-file", str(tmp_path / "hosts"), "--state-path", str(tmp_path / "state.json")],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=environment,
    )


def answer(port: int, name: str) -> bytes | None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(1)
        client.sendto(dns_query(name), ("127.0.0.1", port))
        try:
            return client.recv(512)
        except (TimeoutError, ConnectionResetError):
            return None


def blocked(port: int, name: str) -> bool:
    """A local block answer: NOERROR, one A record, 0.0.0.0 (no block page configured)."""
    reply = answer(port, name)
    return reply is not None and reply[3] & 0x0F == 0 and reply[6:8] == b"\x00\x01" and reply[-4:] == b"\x00\x00\x00\x00"


def wait_for(condition, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.3)
    return False


def stop(process: subprocess.Popen) -> str:
    """Stop the agent and return the end of its log for failure messages."""
    process.terminate()
    _, stderr = process.communicate(timeout=15)
    return stderr.decode(errors="replace")[-2000:]


def test_agent_downloads_blocks_respects_allowed_and_keeps_categories_offline(native, tmp_path):
    categories = tmp_path / "published"
    build_categories(ut1(tmp_path), categories, now=datetime(2026, 10, 23, tzinfo=UTC))
    port = free_port()
    with live_server(category_dir=categories) as (_, origin, client):
        policy = {"web_filter": {"blocked_categories": ["games"], "allowed": ["store.steampowered.com"]}}
        assert client.post("/api/v1/profiles/Default", json=policy).status_code == 200
        agent = start_agent(native, origin, tmp_path, port)
        try:
            if not wait_for(lambda: blocked(port, "api.steampowered.com"), 30):
                raise AssertionError("category did not reach DNS answers:\n" + stop(agent))
            assert blocked(port, "steamcommunity.com")
            assert not blocked(port, "store.steampowered.com"), "allowed wins over the category"
            assert not blocked(port, "example.org")
            cached = list((tmp_path / "categories").glob("games-*.bin"))
            assert len(cached) == 1 and cached[0].read_bytes() == next(categories.glob("games-*.bin")).read_bytes()
            # The policy reaches state.json at the next enforcement cycle, shortly after the sync.
            state = tmp_path / "state.json"
            assert wait_for(lambda: state.exists() and "blocked_categories" in state.read_text(encoding="utf-8"), 15)
        finally:
            stop(agent)
    # Same server address, now gone: the cached category keeps blocking after a restart.
    # (State belongs to one server, so a different address would correctly start from scratch.)
    offline = start_agent(native, origin, tmp_path, port)
    try:
        if not wait_for(lambda: blocked(port, "api.steampowered.com"), 20):
            raise AssertionError("cached category was not used offline:\n" + stop(offline))
    finally:
        stop(offline)


def test_agent_rejects_a_category_file_that_does_not_match_its_digest(native, tmp_path):
    categories = tmp_path / "published"
    manifest = build_categories(ut1(tmp_path), categories, now=datetime(2026, 10, 23, tzinfo=UTC))
    digest = manifest["categories"][0]["digest"]
    port = free_port()
    with live_server(category_dir=categories) as (_, origin, client):
        policy = {"web_filter": {"blocked_categories": ["games"]}}
        assert client.post("/api/v1/profiles/Default", json=policy).status_code == 200
        # Tamper after publication: the server refuses it and the agent never blocks from bad data.
        (categories / f"games-{digest}.bin").write_bytes(b"OEMSCAT1" + (0).to_bytes(4, "big"))
        agent = start_agent(native, origin, tmp_path, port)
        try:
            assert wait_for(lambda: answer(port, "example.org") is not None, 15)
            time.sleep(3)
            assert not blocked(port, "api.steampowered.com")
            assert not list((tmp_path / "categories").glob("games-*.bin"))
        finally:
            stop(agent)
