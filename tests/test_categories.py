"""Reference semantics for web categories: taxonomy, hashed category files and decisions."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest
from agent.categories import build_category_file, parse_category_file

from agent.policy import (
    CATEGORIES,
    domain_blocked_at,
    domain_hash,
    in_category,
    validate_policy,
)


def web(**settings):
    return validate_policy({"web_filter": settings})["web_filter"]


def hashes(*domains):
    return parse_category_file(build_category_file(domains))


def test_taxonomy_maps_ut1_sources_into_fortiguard_style_groups():
    assert {"adult", "gambling", "games", "social", "malware", "phishing"} <= set(CATEGORIES)
    assert CATEGORIES["games"]["sources"] == ["games"]
    assert "social_networks" in CATEGORIES["social"]["sources"]
    assert all(entry["label"] and entry["group"] and entry["sources"] for entry in CATEGORIES.values())
    sources = [source for entry in CATEGORIES.values() for source in entry["sources"]]
    assert len(sources) == len(set(sources)), "each UT1 list feeds one category"


def test_domain_hash_is_the_first_eight_bytes_of_sha256_of_the_normalized_name():
    expected = int.from_bytes(hashlib.sha256(b"steampowered.com").digest()[:8], "big")
    assert domain_hash("SteamPowered.COM") == expected


def test_category_file_is_sorted_unique_and_skips_invalid_entries():
    data = build_category_file(["b.example", "a.example", "A.example", "not a domain", "*.bad", ""])
    assert data[:8] == b"OEMSCAT1"
    parsed = parse_category_file(data)
    assert parsed == sorted({domain_hash("a.example"), domain_hash("b.example")})
    assert int.from_bytes(data[8:12], "big") == 2 and len(data) == 12 + 8 * 2


@pytest.mark.parametrize("data", [b"", b"OEMSCAT0" + bytes(4), b"OEMSCAT1" + (1).to_bytes(4, "big"),
                                  b"OEMSCAT1" + (2).to_bytes(4, "big") + (5).to_bytes(8, "big") * 2,
                                  b"OEMSCAT1" + (2).to_bytes(4, "big") + (9).to_bytes(8, "big") + (5).to_bytes(8, "big")])
def test_corrupt_category_files_are_rejected(data):
    with pytest.raises(ValueError):
        parse_category_file(data)


def test_membership_covers_the_listed_domain_and_its_subdomains_only():
    games = hashes("steampowered.com")
    assert in_category("steampowered.com", games)
    assert in_category("store.steampowered.com", games)
    assert not in_category("notsteampowered.com", games)
    assert not in_category("com", games)


def test_categories_block_with_allowed_exceptions_and_schedules():
    categories = {"games": hashes("steampowered.com"), "social": hashes("facebook.com")}
    settings = web(blocked_categories=["games"], allowed=["store.steampowered.com"], timezone="UTC",
                   scheduled=[{"blocked_categories": ["social"], "days": ["mon"], "from": "08:00", "to": "18:00"}])
    monday_noon, monday_night = datetime(2026, 10, 26, 12, tzinfo=UTC), datetime(2026, 10, 26, 19, tzinfo=UTC)
    assert domain_blocked_at("steamcommunity.com", settings, monday_night, {"games": hashes("steamcommunity.com")})
    assert domain_blocked_at("api.steampowered.com", settings, monday_night, categories)
    assert not domain_blocked_at("store.steampowered.com", settings, monday_night, categories)
    assert domain_blocked_at("www.facebook.com", settings, monday_noon, categories)
    assert not domain_blocked_at("www.facebook.com", settings, monday_night, categories)
    assert not domain_blocked_at("api.steampowered.com", settings, monday_night, {}), "missing data never blocks"


@pytest.mark.parametrize("settings", [
    {"blocked_categories": ["altavista"]},
    {"blocked_categories": ["games", "games"]},
    {"blocked_categories": "games"},
    {"timezone": "UTC", "scheduled": [{"days": ["mon"], "from": "08:00", "to": "18:00"}]},
    {"timezone": "UTC", "scheduled": [{"blocked_categories": ["nope"], "days": ["mon"], "from": "08:00", "to": "18:00"}]},
    {"timezone": "UTC", "scheduled": [{"blocked_categories": [{"x": 1}], "days": ["mon"], "from": "08:00", "to": "18:00"}]},
])
def test_invalid_category_settings_are_rejected(settings):
    with pytest.raises(ValueError):
        validate_policy({"web_filter": settings})


def test_windows_may_use_rules_categories_or_both():
    settings = web(timezone="UTC", scheduled=[{"blocked_categories": ["games"], "days": ["mon"], "from": "08:00", "to": "18:00"},
                                               {"blocked": ["x.example"], "blocked_categories": [], "days": ["tue"], "from": "08:00", "to": "09:00"}])
    assert settings["scheduled"][0] == {"blocked_categories": ["games"], "days": ["mon"], "from": "08:00", "to": "18:00"}
