"""Inert plans describe real DNS and persisted-event acceptance, never its outcome."""

from copy import deepcopy
from datetime import UTC, datetime

import pytest

from agent.policy import domain_hash, validate_policy, web_decision
from tools.ordered_domain_acceptance import add_canary, build_cases

NOW = datetime(2026, 11, 23, 12, tzinfo=UTC)
CATEGORIES = {
    "games": sorted(domain_hash(name) for name in ("www.example.net", "iana.org", "www.iana.org")),
    "streaming": sorted(domain_hash(name) for name in ("www.example.org", "www.icann.org")),
    "shopping": sorted(domain_hash(name) for name in ("www.ietf.org", "www.icann.org")),
}


def cases_by_key():
    return {case["key"]: case for case in build_cases()}


def observations(case):
    return {item["domain"]: item for item in case["expectations"]}


def test_plan_contains_eight_distinct_publishable_policies_without_claiming_acceptance():
    cases = build_cases()
    assert len(cases) == len({case["key"] for case in cases}) == 8
    for case in cases:
        assert set(case) == {"key", "policy", "expectations"}
        assert validate_policy(case["policy"]) == case["policy"]
        assert case["policy"]["web_filter"]["domain_rules"]
        assert not case["policy"]["web_filter"].get("blocked")
        assert not case["policy"]["web_filter"].get("allowed")


def test_simple_and_wildcard_cover_real_root_www_and_deep_names():
    cases = cases_by_key()
    simple = observations(cases["simple-scope"])
    wildcard = observations(cases["wildcard-scope"])
    assert {domain: item["dns"] for domain, item in simple.items()} == {
        "ietf.org": "blocked", "www.ietf.org": "blocked", "datatracker.ietf.org": "forwarded",
    }
    assert all(wildcard[domain]["dns"] == "blocked" for domain in simple)


@pytest.mark.parametrize("key,expected", [
    ("allow-before-block", "allow"), ("block-before-allow", "block"),
    ("monitor-before-block", "monitor"),
])
def test_overlapping_patterns_exercise_first_match_including_monitor(key, expected):
    case = cases_by_key()[key]
    for domain in ("ietf.org", "www.ietf.org"):
        assert observations(case)[domain]["action"] == expected
    assert observations(case)["datatracker.ietf.org"]["action"] == "block"


@pytest.mark.parametrize("key,expected", [
    ("allow-over-blocked-category", "allow"), ("monitor-over-blocked-category", "monitor"),
])
def test_ordered_exception_overrides_confirmed_synthetic_games_membership(key, expected):
    case = cases_by_key()[key]
    assert case["policy"]["web_filter"]["category_actions"]["games"] == "block"
    for domain in ("iana.org", "www.iana.org"):
        assert observations(case)[domain]["action"] == expected
    assert observations(case)["www.example.net"]["event"] == {
        "action": "blocked", "reason": "category", "category": "games", "source": "dns",
    }


def test_unmatched_table_entries_fall_through_to_all_category_actions_and_monitor_all():
    expected = observations(cases_by_key()["category-fallback"])
    assert expected["www.example.net"]["event"]["action"] == "monitored"
    assert expected["www.example.org"]["event"]["action"] == "blocked"
    assert expected["www.ietf.org"]["event"] is None
    assert expected["www.icann.org"]["event"]["category"] == "streaming"
    assert expected["datatracker.ietf.org"]["event"] == {
        "action": "monitored", "reason": "policy", "category": "", "source": "dns",
    }


def test_every_declared_dns_and_event_expectation_agrees_with_real_policy_engine():
    for case in build_cases():
        for expected in case["expectations"]:
            decision = web_decision(expected["domain"], case["policy"]["web_filter"], NOW, CATEGORIES)
            assert decision["action"] == expected["action"], (case["key"], expected)
            assert expected["dns"] == ("blocked" if decision["action"] == "block" else "forwarded")
            if decision["log"]:
                assert expected["event"] == {
                    "action": "blocked" if decision["action"] == "block" else "monitored",
                    "reason": "policy" if decision["reason"] == "observation" else decision["reason"],
                    "category": decision["category"] or "", "source": "dns",
                }
            else:
                assert expected["event"] is None


def test_reordering_first_match_policy_breaks_the_original_acceptance_expectation():
    case = cases_by_key()["monitor-before-block"]
    case["policy"]["web_filter"]["domain_rules"].reverse()
    changed = validate_policy(case["policy"])
    expected = observations(case)["www.ietf.org"]
    assert web_decision(expected["domain"], changed["web_filter"], NOW)["action"] != expected["action"]


def test_each_generated_plan_owns_its_mutable_data():
    first = build_cases()
    first[0]["policy"]["web_filter"]["domain_rules"].clear()
    first[0]["expectations"].clear()
    assert build_cases()[0]["policy"]["web_filter"]["domain_rules"]
    assert build_cases()[0]["expectations"]


def test_canary_appends_ordered_simple_block_without_mutation_or_legacy_mix():
    for case in build_cases():
        original = deepcopy(case["policy"])
        combined = add_canary(original, "Canary.example.com")
        assert original == case["policy"]
        assert combined["web_filter"]["domain_rules"] == [
            *original["web_filter"]["domain_rules"],
            {"domain": "canary.example.com", "type": "simple", "action": "block"},
        ]
        assert validate_policy(combined) == combined
        for domain in ("canary.example.com", "www.canary.example.com"):
            assert web_decision(domain, combined["web_filter"], NOW, CATEGORIES) == {
                "action": "block", "reason": "rule", "category": None, "log": True,
            }


@pytest.mark.parametrize("domain", [None, [], {}, 1, True, "", "*.example.com", "https://example.com",
                                    "127.0.0.1", "example.com\n", "example.com."])
def test_canary_rejects_untrusted_name_types_and_invalid_domains(domain):
    with pytest.raises(ValueError):
        add_canary({}, domain)


@pytest.mark.parametrize("body", [None, [], "policy", {"web_filter": None},
                                  {"web_filter": {"domain_rules": "rules"}},
                                  {"web_filter": {"blocked": ["example.org"]}},
                                  {"web_filter": {"allowed": ["example.org"]}}])
def test_canary_rejects_invalid_or_ambiguous_policy_inputs(body):
    with pytest.raises(ValueError):
        add_canary(body, "canary.example.com")


@pytest.mark.parametrize("domain,kind,canary", [
    ("example.com", "wildcard", "canary.example.com"),
    ("example.com", "simple", "example.com"),
    ("example.com", "simple", "www.example.com"),
    ("www.example.com", "simple", "example.com"),
])
@pytest.mark.parametrize("action", ["allow", "block", "monitor"])
def test_canary_rejects_prior_rules_that_would_shadow_any_canary_query(domain, kind, canary, action):
    body = {"web_filter": {"domain_rules": [{"domain": domain, "type": kind, "action": action}]}}
    with pytest.raises(ValueError, match="canary.*(covered|shadow)"):
        add_canary(body, canary)


def test_canary_can_create_an_ordered_table_for_an_empty_policy():
    combined = add_canary({}, "canary.example.com")
    assert combined["web_filter"]["domain_rules"] == [
        {"domain": "canary.example.com", "type": "simple", "action": "block"},
    ]
