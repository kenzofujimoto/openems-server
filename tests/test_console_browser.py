"""Behavioral browser checks for the management console, without a live EMS."""

from __future__ import annotations

import functools
import json
import re
import threading
from collections.abc import Iterator
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
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
def page(console_coverage: list[list[dict]]) -> Iterator[Page]:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context()
        tab = context.new_page()
        profiler = context.new_cdp_session(tab)
        profiler.send("Profiler.enable")
        profiler.send("Profiler.startPreciseCoverage", {"callCount": False, "detailed": True})
        yield tab
        coverage = profiler.send("Profiler.takePreciseCoverage")
        for script in coverage["result"]:
            if urlsplit(script["url"]).path.endswith("/console.js"):
                console_coverage.append([
                    block for function in script["functions"] for block in function["ranges"]
                ])
        context.close()
        browser.close()


@pytest.fixture(scope="module")
def console_coverage() -> Iterator[list[list[dict]]]:
    """Merge V8's executed source ranges, including nested unexecuted branches."""
    runs: list[list[dict]] = []
    yield runs
    source = Path(__file__).resolve().parents[1] / "app" / "static" / "console.js"
    length = len(source.read_text(encoding="utf-8"))
    boundaries = sorted({0, length} | {
        value for run in runs for block in run
        for value in (block["startOffset"], block["endOffset"])
    })
    executed = 0
    for start, end in zip(boundaries, boundaries[1:], strict=False):
        for run in runs:
            containing = [block for block in run if block["startOffset"] <= start and block["endOffset"] >= end]
            if containing and min(containing, key=lambda block: block["endOffset"] - block["startOffset"])["count"] > 0:
                executed += end - start
                break
    percentage = 100 * executed / length
    report = {"source": "app/static/console.js", "total_bytes": length, "executed_bytes": executed, "percent": round(percentage, 2)}
    report_path = source.parents[2] / ".pytest_cache" / "console-coverage.json"
    report_path.parent.mkdir(exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    assert percentage >= 80, f"Console JavaScript executed-range coverage {percentage:.2f}% < 80%; see {report_path}"


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


def test_cookie_session_removes_legacy_token_and_sends_csrf(
    page: Page, console_url: str,
) -> None:
    page.add_init_script("localStorage.setItem('openems_token', 'obsolete-secret')")
    rule = {"id": "safe", "target_vdom": "Strict", "priority": 0, "enabled": False, "conditions": []}
    requests = []
    page.on("request", lambda request: requests.append(request))
    mock_api(page, [], [rule])
    page.goto(console_url)
    page.locator("#rules").get_by_role("button", name="Edit", exact=True).click()
    page.get_by_role("button", name="Save rule", exact=True).click()
    expect(page.locator("#toast")).to_contain_text("saved")
    writes = [request for request in requests if request.method == "POST"]
    assert writes[0].headers.get("x-csrf-token") == "test-csrf"
    assert all("authorization" not in request.headers for request in requests)
    assert page.evaluate("localStorage.getItem('openems_token')") is None


@pytest.mark.parametrize("role,can_write", [("superadmin", True), ("viewer", False)])
def test_role_permissions_are_reflected_in_controls(
    page: Page, console_url: str, role: str, can_write: bool,
) -> None:
    mock_api(page, [], [])
    page.route("**/api/v1/auth/session", lambda route: route.fulfill(json={
        "username": "user", "role": role, "csrf_token": "test-csrf",
    }))
    page.goto(console_url)
    expect(page.locator("#session-user")).to_contain_text(role)
    expect(page.get_by_role("button", name="Publish", exact=True)).to_be_enabled(enabled=can_write)
    expect(page.get_by_role("button", name="Save rule", exact=True)).to_be_enabled(enabled=can_write)


def test_policy_is_applied_only_after_exact_confirmation_and_errors_are_visible(
    page: Page, console_url: str,
) -> None:
    endpoint = {
        "devid": "lab", "hostname": "lab", "os": "Windows", "host_tags": [],
        "online": True, "effective_vdom": "Strict", "config_version": 1,
        "applied_vdom": "Other", "applied_digest": "digest",
        "desired_profile": {"vdom": "Strict", "version": 1, "digest": "digest"},
        "last_seen": "2026-10-22T12:00:00+00:00", "last_applied": "2026-10-22T12:00:00+00:00",
    }
    mock_api(page, [endpoint], [])
    page.goto(console_url)
    expect(page.locator("#endpoints")).to_contain_text("Pending")
    endpoint["applied_vdom"] = "Strict"
    page.get_by_role("button", name="Refresh", exact=True).click()
    expect(page.locator("#endpoints")).to_contain_text("Applied")
    endpoint["last_error"] = "hosts permission denied"
    endpoint["online"] = False
    page.get_by_role("button", name="Refresh", exact=True).click()
    expect(page.locator("#endpoints")).to_contain_text("Error")
    expect(page.locator("#endpoints")).to_contain_text("Offline")
    page.locator("#endpoints").get_by_role("button", name="lab", exact=True).focus()
    page.keyboard.press("Enter")
    expect(page.get_by_role("dialog", name="Endpoint detail")).to_be_visible()
    expect(page.locator("#detail")).to_contain_text("hosts permission denied")
    page.keyboard.press("Escape")
    expect(page.get_by_role("dialog", name="Endpoint detail")).not_to_be_visible()


def test_failed_refresh_keeps_previous_data_and_retry_recovers(
    page: Page, console_url: str,
) -> None:
    mock_api(page, [{"devid": "still-visible", "hostname": "lab", "online": True}], [])
    page.goto(console_url)
    expect(page.locator("#endpoints")).to_contain_text("still-visible")
    failing = True

    def endpoint_route(route: Route) -> None:
        if failing:
            route.fulfill(status=503, json={"detail": "maintenance"})
        else:
            route.fulfill(json=[{"devid": "recovered", "online": True}])

    page.route("**/api/v1/endpoints/index", endpoint_route)
    page.get_by_role("button", name="Refresh", exact=True).click()
    expect(page.locator("#endpoints-error")).to_contain_text("outdated")
    expect(page.locator("#endpoints")).to_contain_text("still-visible")
    failing = False
    page.get_by_role("button", name="Retry endpoints").click()
    expect(page.locator("#endpoints")).to_contain_text("recovered")
    expect(page.locator("#endpoints-error")).not_to_be_visible()


def test_policy_form_validates_and_publishes_explicit_blocks(
    page: Page, console_url: str,
) -> None:
    mock_api(page, [], [])
    writes = []

    def publish(route: Route) -> None:
        writes.append(route.request.post_data_json)
        assert route.request.headers["x-csrf-token"] == "test-csrf"
        route.fulfill(json={"version": 2})

    page.route("**/api/v1/profiles/Default", publish)
    page.goto(console_url)
    page.get_by_label("Blocked domains (one per line)").fill("https://example.com/path")
    page.get_by_role("button", name="Publish", exact=True).click()
    expect(page.locator("#profile-error")).to_contain_text("Invalid domain")
    assert writes == []
    page.get_by_label("Blocked domains (one per line)").fill("EXAMPLE.COM\nexample.com")
    page.get_by_label("Blocked process names (one per line)").fill("sample.exe")
    page.get_by_role("button", name="Publish", exact=True).click()
    expect(page.locator("#toast")).to_contain_text("v2 published")
    assert writes == [{"web_filter": {"blocked": ["example.com"]}, "app_control": {"blocked": ["sample.exe"]}}]
    page.get_by_text("Advanced JSON", exact=True).click()
    page.get_by_label("Publish JSON instead of the fields above").check()
    page.get_by_label("Policy JSON (web_filter and app_control)").fill(json.dumps({"firewall": "on"}))
    page.get_by_role("button", name="Publish", exact=True).click()
    expect(page.locator("#profile-error")).to_contain_text("Unsupported policy section")
    assert len(writes) == 1
