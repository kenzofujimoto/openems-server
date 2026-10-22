"""Security regressions for SAML trust, correlation and shared storage."""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from app.saml import IdpConfig, SamlError, SamlSp, parse_saml_response


def test_default_parser_refuses_unsigned_response() -> None:
    xml = ('<p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" '
           'xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion">'
           '<p:Status><p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
           '</p:Status><s:Assertion><s:Subject><s:NameID>attacker</s:NameID>'
           '</s:Subject></s:Assertion></p:Response>')
    with pytest.raises(SamlError, match="signature"):
        parse_saml_response(base64.b64encode(xml.encode()).decode())


def test_idp_store_survives_sp_recreation() -> None:
    from app.idp_store import InMemoryIdpStore

    store = InMemoryIdpStore()
    first = SamlSp("https://ems.example", idp_store=store)
    idp = IdpConfig("https://idp.example", "https://idp.example/sso", "certificate")
    first.register_idp("acme", idp)
    second = SamlSp("https://ems.example", idp_store=store)
    assert second.login_redirect("acme").startswith(idp.sso_url)


def test_pending_request_is_bound_and_atomically_consumed() -> None:
    from app.replay import InMemoryPendingRequestStore

    store = InMemoryPendingRequestStore()
    store.put("request", "acme", "opaque", datetime.now(timezone.utc) + timedelta(minutes=1))
    assert not store.consume("request", "other", "opaque")
    assert not store.consume("request", "acme", "wrong")
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: store.consume("request", "acme", "opaque"), range(20)))
    assert results.count(True) == 1


def test_pending_request_expiry_is_enforced() -> None:
    from app.replay import InMemoryPendingRequestStore

    store = InMemoryPendingRequestStore()
    store.put("expired", "acme", None, datetime.now(timezone.utc) - timedelta(seconds=1))
    assert not store.consume("expired", "acme", None)
