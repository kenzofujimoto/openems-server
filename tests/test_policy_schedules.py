"""Reference semantics for forced SafeSearch and scheduled web filter rules."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agent.policy import (
    GOOGLE_DOMAINS,
    domain_blocked_at,
    hosts_names_at,
    safe_search_target,
    validate_policy,
)

WORKDAYS = ["mon", "tue", "wed", "thu", "fri"]
SOCIAL = {"blocked": ["*.facebook.com"], "days": WORKDAYS, "from": "08:00", "to": "18:00"}


def web(**settings):
    return validate_policy({"web_filter": settings})["web_filter"]


def utc(text: str) -> datetime:
    return datetime.fromisoformat(text).replace(tzinfo=UTC)


def test_valid_safe_search_and_schedule_are_normalized():
    settings = web(blocked=["Example.com"], safe_search={"engines": ["google", "youtube"], "youtube": "moderate"},
                   timezone="America/Sao_Paulo", scheduled=[{**SOCIAL, "blocked": ["*.Facebook.com", "*.facebook.com"]}])
    assert settings["scheduled"] == [SOCIAL]
    assert settings["safe_search"] == {"engines": ["google", "youtube"], "youtube": "moderate"}


@pytest.mark.parametrize("settings", [
    {"safe_search": {"engines": ["altavista"]}},
    {"safe_search": {"engines": ["google", "google"]}},
    {"safe_search": {"engines": ["google"], "youtube": "lenient"}},
    {"safe_search": {"engines": ["google"], "extra": True}},
    {"safe_search": ["google"]},
    {"scheduled": [SOCIAL]},
    {"timezone": "Mars/Olympus", "scheduled": [SOCIAL]},
    {"timezone": "../etc/passwd", "scheduled": [SOCIAL]},
    {"timezone": "America/Sao_Paulo", "scheduled": [{**SOCIAL, "from": "18:00", "to": "08:00"}]},
    {"timezone": "America/Sao_Paulo", "scheduled": [{**SOCIAL, "from": "8:00"}]},
    {"timezone": "America/Sao_Paulo", "scheduled": [{**SOCIAL, "to": "24:00"}]},
    {"timezone": "America/Sao_Paulo", "scheduled": [{**SOCIAL, "days": []}]},
    {"timezone": "America/Sao_Paulo", "scheduled": [{**SOCIAL, "days": ["mon", "mon"]}]},
    {"timezone": "America/Sao_Paulo", "scheduled": [{**SOCIAL, "days": ["funday"]}]},
    {"timezone": "America/Sao_Paulo", "scheduled": [{**SOCIAL, "blocked": ["*.com"]}]},
    {"timezone": "America/Sao_Paulo", "scheduled": [{**SOCIAL, "note": "x"}]},
    {"timezone": "America/Sao_Paulo", "scheduled": [SOCIAL] * 51},
])
def test_invalid_safe_search_or_schedule_is_rejected(settings):
    with pytest.raises(ValueError):
        validate_policy({"web_filter": settings})


def test_schedule_uses_policy_timezone_with_exclusive_end():
    settings = web(timezone="America/Sao_Paulo", scheduled=[SOCIAL])
    # 2026-10-26 is a Monday; Sao Paulo is UTC-3.
    assert not domain_blocked_at("www.facebook.com", settings, utc("2026-10-26T10:59:00"))
    assert domain_blocked_at("www.facebook.com", settings, utc("2026-10-26T11:00:00"))
    assert domain_blocked_at("www.facebook.com", settings, utc("2026-10-26T20:59:00"))
    assert not domain_blocked_at("www.facebook.com", settings, utc("2026-10-26T21:00:00"))
    assert not domain_blocked_at("www.facebook.com", settings, utc("2026-10-25T14:00:00"))  # Sunday


def test_allowed_wins_over_scheduled_and_unscheduled_rules_always_apply():
    settings = web(blocked=["*.example.com"], allowed=["m.facebook.com"], timezone="UTC", scheduled=[SOCIAL])
    monday_noon = utc("2026-10-26T12:00:00")
    assert not domain_blocked_at("m.facebook.com", settings, monday_noon)
    assert domain_blocked_at("a.example.com", settings, utc("2026-10-25T03:00:00"))


def test_hosts_mode_follows_active_windows():
    settings = web(blocked=["other.org"], timezone="UTC", scheduled=[SOCIAL])
    assert hosts_names_at(settings, utc("2026-10-26T12:00:00")) == ["other.org", "www.other.org", "facebook.com", "www.facebook.com"]
    assert hosts_names_at(settings, utc("2026-10-26T19:00:00")) == ["other.org", "www.other.org"]


def test_safe_search_targets_cover_each_engine_only_when_enabled():
    settings = web(safe_search={"engines": ["google", "bing", "youtube", "duckduckgo"]})
    assert safe_search_target("www.google.com", settings) == "forcesafesearch.google.com"
    assert safe_search_target("Google.com.BR", settings) == "forcesafesearch.google.com"
    assert safe_search_target("www.youtube.com", settings) == "restrict.youtube.com"
    assert safe_search_target("youtubei.googleapis.com", settings) == "restrict.youtube.com"
    assert safe_search_target("www.bing.com", settings) == "strict.bing.com"
    assert safe_search_target("duckduckgo.com", settings) == "safe.duckduckgo.com"
    for name in ("mail.google.com", "forcesafesearch.google.com", "example.org", "not a name"):
        assert safe_search_target(name, settings) is None
    moderate = web(safe_search={"engines": ["youtube"], "youtube": "moderate"})
    assert safe_search_target("m.youtube.com", moderate) == "restrictmoderate.youtube.com"
    assert safe_search_target("www.google.com", moderate) is None
    assert safe_search_target("www.google.com", web()) is None


def test_google_domain_list_is_the_published_one():
    assert len(GOOGLE_DOMAINS) == 187
    assert GOOGLE_DOMAINS[0] == "google.com" and "google.com.br" in GOOGLE_DOMAINS
    assert all(domain.startswith("google.") for domain in GOOGLE_DOMAINS)


@pytest.mark.parametrize("settings", [
    {"safe_search": {"engines": [{"name": "google"}]}},
    {"timezone": "UTC", "scheduled": [{**SOCIAL, "days": [["mon"]]}]},
])
def test_unhashable_entries_are_validation_errors_not_crashes(settings):
    with pytest.raises(ValueError):
        validate_policy({"web_filter": settings})
