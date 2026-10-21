"""Tests for SAML assertion conditions (NotBefore/NotOnOrAfter/Audience) and
replay protection."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest

from app.replay import InMemoryReplayCache
from app.saml import (
    IdpConfig,
    SamlError,
    SamlSp,
    parse_saml_response,
    validate_conditions,
)

SP_BASE = "https://ems.example"
SP_AUDIENCE = f"{SP_BASE}/fct_saml/acme/metadata"


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _response(
    *,
    assertion_id: str = "_a1",
    not_before: datetime | None = None,
    not_on_or_after: datetime | None = None,
    audience: str | None = SP_AUDIENCE,
) -> str:
    cond_attrs = ""
    if not_before is not None:
        cond_attrs += f' NotBefore="{_iso(not_before)}"'
    if not_on_or_after is not None:
        cond_attrs += f' NotOnOrAfter="{_iso(not_on_or_after)}"'
    aud = (
        f"<saml:AudienceRestriction><saml:Audience>{audience}"
        "</saml:Audience></saml:AudienceRestriction>"
        if audience is not None
        else ""
    )
    return (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
        '<samlp:Status><samlp:StatusCode '
        'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        f'<saml:Assertion ID="{assertion_id}">'
        "<saml:Subject><saml:NameID>dave@example.com</saml:NameID></saml:Subject>"
        f"<saml:Conditions{cond_attrs}>{aud}</saml:Conditions>"
        "</saml:Assertion></samlp:Response>"
    )


def _b64(xml: str) -> str:
    return base64.b64encode(xml.encode()).decode()


# --- validate_conditions (unit) ----------------------------------------

def test_parse_populates_conditions() -> None:
    now = datetime.now(timezone.utc)
    a = parse_saml_response(_b64(_response(
        not_before=now - timedelta(minutes=5),
        not_on_or_after=now + timedelta(minutes=5),
    )))
    assert a.assertion_id == "_a1"
    assert a.audiences == [SP_AUDIENCE]
    assert a.not_on_or_after is not None


def test_expired_assertion_rejected() -> None:
    now = datetime.now(timezone.utc)
    a = parse_saml_response(_b64(_response(not_on_or_after=now - timedelta(hours=1))))
    with pytest.raises(SamlError):
        validate_conditions(a, now=now)


def test_not_yet_valid_assertion_rejected() -> None:
    now = datetime.now(timezone.utc)
    a = parse_saml_response(_b64(_response(not_before=now + timedelta(hours=1))))
    with pytest.raises(SamlError):
        validate_conditions(a, now=now)


def test_audience_mismatch_rejected() -> None:
    a = parse_saml_response(_b64(_response(audience="https://someone-else")))
    with pytest.raises(SamlError):
        validate_conditions(a, audience=SP_AUDIENCE)


def test_valid_window_and_audience_ok() -> None:
    now = datetime.now(timezone.utc)
    a = parse_saml_response(_b64(_response(
        not_before=now - timedelta(minutes=1),
        not_on_or_after=now + timedelta(minutes=5),
    )))
    validate_conditions(a, audience=SP_AUDIENCE, now=now)  # no raise


def test_require_audience_with_none_rejected() -> None:
    a = parse_saml_response(_b64(_response(audience=None)))
    with pytest.raises(SamlError):
        validate_conditions(a, audience=SP_AUDIENCE, require_audience=True)


# --- SamlSp integration -------------------------------------------------

def _sp() -> SamlSp:
    sp = SamlSp(SP_BASE)  # signature off; focus on conditions/replay
    sp.register_idp("acme", IdpConfig("https://idp.example", "https://idp.example/sso"))
    return sp


def test_samlsp_rejects_expired() -> None:
    now = datetime.now(timezone.utc)
    sp = _sp()
    with pytest.raises(SamlError):
        sp.consume(
            "acme",
            _b64(_response(not_on_or_after=now - timedelta(hours=1))),
            now=now,
        )


def test_samlsp_rejects_replay() -> None:
    now = datetime.now(timezone.utc)
    sp = _sp()
    resp = _b64(_response(
        assertion_id="_unique1", not_on_or_after=now + timedelta(minutes=5)
    ))
    first = sp.consume("acme", resp, now=now)
    assert first.name_id == "dave@example.com"
    with pytest.raises(SamlError):
        sp.consume("acme", resp, now=now)  # same ID again -> replay


# --- replay cache contract ---------------------------------------------

def test_inmemory_replay_cache_remembers_once() -> None:
    cache = InMemoryReplayCache()
    exp = datetime.now(timezone.utc) + timedelta(minutes=5)
    assert cache.check_and_remember("id-1", exp) is True
    assert cache.check_and_remember("id-1", exp) is False
    assert cache.check_and_remember("id-2", exp) is True
