"""Behavioral browser checks for the management console, without a live EMS."""

from __future__ import annotations

import functools
import re
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import Page, Route, expect, sync_playwright


@pytest.fixture(scope="module")
def console_url() -> Iterator[str]:
    static = Path(__file__).resolve().parents[1] / "app" / "static"
    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(static))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/index.html"
    server.shutdown()
    server.server_close()
    thread.join()


@pytest.fixture
def page() -> Iterator[Page]:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context()
        tab = context.new_page()
        yield tab
        context.close()
        browser.close()


def mock_api(page: Page, endpoints: list[dict], rules: list[dict]) -> list[dict]:
    writes: list[dict] = []

    def route_api(route: Route) -> None:
        path = urlsplit(route.request.url).path
        if path == "/api/v1/auth/session":
            result = {"username": "admin", "role": "admin", "csrf_token": "test-csrf"}
        elif path == "/api/v1/endpoints/index":
            result = endpoints
        elif path == "/api/v1/endpoints/count":
            result = {"count": len(endpoints)}
        elif path == "/api/v1/endpoints/detail":
            result = endpoints[0]
        elif path == "/api/v1/assignment_rules":
            if route.request.method == "POST":
                result = route.request.post_data_json
                writes.append(result)
            else:
                result = rules
        elif path in {"/api/v1/profiles", "/api/v1/audit"}:
            result = []
        else:
            route.fulfill(status=404, json={"detail": "Unknown test route"})
            return
        route.fulfill(json=result)

    page.route("**/api/v1/**", route_api)
    return writes


def test_device_id_cannot_execute_javascript(page: Page, console_url: str) -> None:
    device_id = "machine');window.__injected=true;//"
    endpoint = {
        "devid": device_id, "hostname": "<img src=x onerror=alert(1)>",
        "os": "Windows", "status": "registered", "host_tags": [],
        "vdom": "Default", "effective_vdom": "Default", "client_id": "public-id",
        "config_version": 0, "current_config_version": 1,
        "online": True, "desired_profile": {"vdom": "Default", "version": 1, "digest": "abc"},
        "last_seen": "2026-10-22T12:00:00+00:00",
    }
    mock_api(page, [endpoint], [])
    page.goto(console_url)
    row = page.locator("#endpoints tr").filter(has_text=device_id)
    expect(row).to_be_visible()
    row.get_by_role("button").click() if row.get_by_role("button").count() else row.click()
    assert page.evaluate("window.__injected === undefined"), "Device ID executed as JavaScript"
    expect(page.locator("#detail")).to_contain_text(device_id)
    assert page.locator("#endpoints img").count() == 0


def test_rule_editor_roundtrip_preserves_all_conditions_and_types(
    page: Page, console_url: str,
) -> None:
    rule = {
        "id": "mixed-rule", "target_vdom": "Strict", "priority": 0, "enabled": False,
        "conditions": [
            {"field": "os", "op": "in", "value": ["Windows 11", "Windows 10"]},
            {"field": "hostname", "op": "contains", "value": "lab"},
        ],
    }
    writes = mock_api(page, [], [rule])
    page.goto(console_url)
    page.locator("#rules").get_by_role("button", name="Edit", exact=True).click()
    page.get_by_role("button", name=re.compile(r"^(Add rule|Save rule)$")).click()
    expect(page.locator("#toast")).to_contain_text(re.compile("saved|added"))
    assert writes == [rule]
