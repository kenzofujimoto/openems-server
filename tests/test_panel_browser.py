"""Production React bundle against a real disposable API, without an installed agent."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from playwright.sync_api import expect, sync_playwright

from app.models import RegisterRequest
from tests.test_agent_integration import live_server
from tests.test_native_agent import INVITATION


@pytest.fixture(scope="module")
def browser():
    assert (Path(__file__).resolve().parents[1] / "app/panel_dist/index.html").is_file(), "Run npm run build in web first"
    with sync_playwright() as playwright, playwright.chromium.launch(headless=True) as instance:
        yield instance


@pytest.fixture
def page(browser):
    with browser.new_context(viewport={"width": 1440, "height": 1000}) as context:
        yield context.new_page()


@pytest.fixture
def server():
    with live_server() as (service, origin, client):
        client.post("/api/v1/profiles/Default", json={
            "web_filter": {"blocked": ["old.example"]}, "app_control": {"blocked": ["legacy.exe"]},
            "usb_control": {"default_action": "allow", "rules": []},
        }).raise_for_status()
        endpoint = service.register(RegisterRequest(devid="browser-pc", hostname="Browser PC", invitation=INVITATION))
        client.post("/api/v1/admins", json={"username": "reader", "password": "reader-test-password", "role": "viewer"}).raise_for_status()
        yield service, origin, client, endpoint


def login(page, origin, username="operator", password="e2e-test-password", path="/panel/"):
    page.goto(origin + path)
    page.get_by_label("Usuário", exact=True).fill(username)
    page.get_by_label("Senha", exact=True).fill(password)
    page.get_by_role("button", name="Entrar", exact=True).click()
    expect(page.get_by_role("button", name=re.compile(username))).to_be_visible()


def test_real_cookie_login_error_and_csrf_logout(page, server):
    _, origin, _, _ = server
    page.goto(origin + "/panel/")
    page.get_by_label("Usuário", exact=True).fill("operator")
    page.get_by_label("Senha", exact=True).fill("incorrect-password")
    page.get_by_role("button", name="Entrar", exact=True).click()
    expect(page.get_by_role("alert")).to_contain_text("Usuário ou senha inválidos")
    page.get_by_label("Senha", exact=True).fill("e2e-test-password")
    page.get_by_role("button", name="Entrar", exact=True).click()
    expect(page.get_by_role("heading", name="Visão geral", exact=True)).to_be_visible()
    assert any(cookie["name"] == "openems_session" and cookie["httpOnly"] for cookie in page.context.cookies())
    assert set(page.evaluate("Object.keys(localStorage)")) <= {"openems-theme"}, "credentials must not be stored in JavaScript storage"
    page.get_by_role("button", name=re.compile("operator")).click()
    with page.expect_request("**/api/v1/auth/logout") as request:
        page.get_by_role("menuitem", name="Sair").click()
    assert request.value.headers.get("x-csrf-token")
    expect(page.get_by_role("heading", name="Entrar", exact=True)).to_be_visible()


def test_real_policy_publication_preserves_other_sections_and_uses_csrf(page, server):
    _, origin, client, _ = server
    login(page, origin, path="/panel/policies/web")
    field = page.get_by_role("textbox", name="Domínios bloqueados", exact=True)
    expect(field).to_have_value("old.example")
    field.fill("https://invalid.example/path")
    page.get_by_role("button", name="Publicar política", exact=True).click()
    expect(page.get_by_role("alert")).to_contain_text("domínio válido")
    field.fill("*.new.example")
    page.get_by_role("textbox", name="Domínios permitidos", exact=True).fill("safe.new.example")
    with page.expect_request(re.compile(r"/api/v1/profiles/Default$")) as request:
        page.get_by_role("button", name="Publicar política", exact=True).click()
    assert request.value.headers.get("x-csrf-token") and request.value.headers.get("if-match")
    expect(page.get_by_role("status")).to_contain_text("v2 publicado")
    profile = next(item for item in client.get("/api/v1/profiles").json() if item["vdom"] == "Default")
    assert profile["body"]["web_filter"]["blocked"] == ["*.new.example"]
    assert profile["body"]["app_control"] == {"blocked": ["legacy.exe"]}
    assert profile["body"]["usb_control"] == {"default_action": "allow", "rules": []}


def test_real_rule_editor_roundtrips_condition_types(page, server):
    _, origin, client, _ = server
    rule = {"id": "mixed-rule", "target_vdom": "Strict", "priority": 10, "enabled": True, "conditions": [
        {"field": "os", "op": "in", "value": ["win32", "linux"]},
        {"field": "hostname", "op": "contains", "value": "Browser"},
    ]}
    client.post("/api/v1/assignment_rules", json=rule).raise_for_status()
    login(page, origin, path="/panel/groups")
    page.get_by_role("button", name="Editar regra mixed-rule", exact=True).click()
    expect(page.get_by_role("textbox", name="Valor da condição 1", exact=True)).to_have_value("win32\nlinux")
    page.get_by_role("textbox", name="Valor da condição 2", exact=True).fill("Changed")
    page.get_by_role("button", name="Salvar regra", exact=True).click()
    expect(page.get_by_role("status")).to_contain_text("mixed-rule salva")
    stored = client.get("/api/v1/assignment_rules").json()[0]
    assert stored["conditions"][0]["value"] == ["win32", "linux"]
    assert stored["conditions"][1]["value"] == "Changed"


def test_endpoint_strings_are_text_and_failed_ack_is_visible(page, server):
    service, origin, _, endpoint = server
    endpoint.hostname = "<img src=x onerror=window.__injected=true>"
    service._store.upsert(endpoint)
    profile = service.get_profile("Default")
    with pytest.raises(ValueError):
        service.ack_config(endpoint.client_id, profile.version, vdom="Default", digest="bad")
    login(page, origin, path="/panel/endpoints")
    row = page.get_by_role("row").filter(has=page.get_by_role("button", name="Abrir browser-pc", exact=True))
    expect(row.get_by_text("Pendente", exact=True)).to_be_visible()
    assert row.locator("img").count() == 0
    assert page.evaluate("window.__injected === undefined")
    service.ack_config(endpoint.client_id, profile.version, vdom="Default", digest=profile.digest)
    page.reload()
    expect(row.get_by_text("Aplicada", exact=True)).to_be_visible()
    service.ack_config(endpoint.client_id, profile.version, vdom="Default", digest=profile.digest,
                       success=False, error="controlled enforcement failure")
    page.reload()
    expect(row.get_by_text("Erro", exact=True)).to_be_visible()
    page.get_by_role("button", name="Abrir browser-pc", exact=True).click()
    expect(page.get_by_role("dialog")).to_contain_text("controlled enforcement failure")


def test_viewer_has_no_policy_writes_and_mobile_navigation_retains_theme(page, server):
    _, origin, _, _ = server
    login(page, origin, "reader", "reader-test-password", "/panel/policies/web")
    expect(page.get_by_role("textbox", name="Domínios bloqueados", exact=True)).to_be_disabled()
    assert page.get_by_role("button", name="Publicar política", exact=True).count() == 0
    page.set_viewport_size({"width": 390, "height": 844})
    page.get_by_role("button", name="Ativar modo escuro", exact=True).click()
    page.reload()
    expect(page.locator("html")).to_have_attribute("data-theme", "dark")
    page.get_by_role("button", name="Abrir navegação", exact=True).focus()
    page.keyboard.press("Enter")
    navigation = page.get_by_role("navigation", name="Navegação móvel", exact=True)
    navigation.get_by_role("link", name="Auditoria", exact=True).click()
    expect(page.get_by_role("heading", name="Auditoria", exact=True)).to_be_visible()
    expect(page.get_by_role("dialog")).not_to_be_visible()
