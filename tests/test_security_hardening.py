"""Hardening found missing in the 2026-10-27 security review (ZAP, Semgrep, manual review)."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.saml import SamlError, parse_idp_metadata, parse_saml_response
from app.service import EmsService

ROOT = Path(__file__).resolve().parents[1]
DTD = '<?xml version="1.0" encoding="{encoding}"?><!DOCTYPE r [<!ENTITY a "aaaa">]><r>&a;</r>'


def client(*, lab_mode: bool = False) -> TestClient:
    return TestClient(create_app(EmsService(require_invitation=False), lab_mode=lab_mode))


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"])
def test_api_schema_and_docs_are_not_public(path):
    # The schema maps every management route; operators read it in laboratory mode only.
    assert client().get(path).status_code == 404


def test_laboratory_mode_still_offers_the_schema_on_loopback():
    response = client(lab_mode=True).get("/openapi.json")
    assert response.status_code == 200 and response.json()["info"]["title"] == "openems-server"


def test_every_response_isolates_the_browsing_context():
    response = client().get("/panel/")
    assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert response.headers["Cross-Origin-Resource-Policy"] == "same-origin"
    assert response.headers["X-Frame-Options"] == "DENY"
    policy = response.headers["Permissions-Policy"]
    for feature in ("camera=()", "microphone=()", "geolocation=()", "usb=()", "payment=()"):
        assert feature in policy
    rejected = client().get("/api/v1/endpoints/index")
    assert rejected.status_code == 401 and rejected.headers["Cross-Origin-Resource-Policy"] == "same-origin"


@pytest.mark.parametrize("encoding,codec,reason", [
    ("UTF-16", "utf-16", "DTD"), ("UTF-16BE", "utf-16-be", "DTD"),
    # Expat cannot decode UTF-32, so the document is refused before any DTD is read.
    ("UTF-32", "utf-32", "not well-formed"),
])
def test_saml_response_rejects_a_dtd_in_any_encoding(encoding, codec, reason):
    # A byte-level "<!DOCTYPE" check misses wide encodings; parsing must refuse the DTD itself.
    payload = base64.b64encode(DTD.format(encoding=encoding).encode(codec)).decode()
    with pytest.raises(SamlError, match=reason):
        parse_saml_response(payload, require_signature=False)


@pytest.mark.parametrize("encoding,codec", [("UTF-16", "utf-16"), ("UTF-32", "utf-32")])
def test_idp_metadata_rejects_a_dtd_in_any_encoding(encoding, codec):
    with pytest.raises(SamlError, match="DTD"):
        parse_idp_metadata(DTD.format(encoding=encoding).encode(codec).decode(codec))


def test_tls_proxy_forwards_the_validated_host_and_security_headers():
    nginx = (ROOT / "deploy" / "nginx.conf").read_text(encoding="utf-8")
    assert "proxy_set_header Host $host;" in nginx and "$http_host" not in nginx
    for header in ("X-Content-Type-Options", "Cross-Origin-Opener-Policy", "Permissions-Policy"):
        assert f"add_header {header}" in nginx
