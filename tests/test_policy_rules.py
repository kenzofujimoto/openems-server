"""Reference semantics for web filter rules: wildcards and the allow list."""

from __future__ import annotations

import pytest

from agent.policy import domain_blocked, hosts_names, normalize_domain_rule, validate_policy


@pytest.mark.parametrize(("value", "expected"), [
    ("example.com", "example.com"),
    ("*.Example.COM", "*.example.com"),
    ("*.bücher.de", "*.xn--bcher-kva.de"),
    ("*.sub.example.co.uk", "*.sub.example.co.uk"),
])
def test_rule_normalization_accepts_exact_and_leading_wildcards(value, expected):
    assert normalize_domain_rule(value) == expected


@pytest.mark.parametrize("value", ["*", "*.", "*.com", "a.*.com", "**.example.com", "*example.com",
                                   "*.example.com.", "*.1.2.3.4", ".example.com", "*.*.example.com"])
def test_rule_normalization_rejects_unsafe_wildcards(value):
    with pytest.raises(ValueError):
        normalize_domain_rule(value)


def test_exact_rule_keeps_domain_and_www_only():
    assert domain_blocked("example.com", ["example.com"], [])
    assert domain_blocked("WWW.Example.com", ["example.com"], [])
    assert not domain_blocked("sub.example.com", ["example.com"], [])


def test_wildcard_covers_apex_and_every_subdomain_but_not_lookalikes():
    rules = ["*.example.com"]
    for name in ("example.com", "www.example.com", "a.b.example.com"):
        assert domain_blocked(name, rules, [])
    for name in ("example.com.br", "notexample.com", "com"):
        assert not domain_blocked(name, rules, [])


def test_allow_list_wins_over_blocking():
    blocked, allowed = ["*.google.com"], ["mail.google.com"]
    assert domain_blocked("docs.google.com", blocked, allowed)
    assert not domain_blocked("mail.google.com", blocked, allowed)
    assert not domain_blocked("www.mail.google.com", blocked, allowed)
    assert domain_blocked("a.mail.google.com", blocked, allowed)
    assert not domain_blocked("x.example.com", ["*.example.com"], ["*.example.com"])


def test_invalid_names_are_never_blocked():
    assert not domain_blocked("not a name", ["*.example.com"], [])
    assert not domain_blocked("127.0.0.1", ["example.com"], [])


def test_hosts_mode_is_best_effort_for_wildcards_and_respects_allowed():
    assert hosts_names(["*.example.com", "other.org"], []) == ["example.com", "www.example.com", "other.org", "www.other.org"]
    assert hosts_names(["example.com"], ["www.example.com"]) == ["example.com"]
    assert hosts_names(["www.example.com", "*.example.com"], []) == ["www.example.com", "example.com"]


def test_policy_accepts_wildcards_and_allowed_and_rejects_bad_entries():
    body = validate_policy({"web_filter": {"blocked": ["*.Example.com", "*.example.com"], "allowed": ["Mail.example.com"]}})
    assert body["web_filter"] == {"blocked": ["*.example.com"], "allowed": ["mail.example.com"]}
    for bad in ({"web_filter": {"allowed": "x.com"}}, {"web_filter": {"allowed": ["*.com"]}},
                {"web_filter": {"blocked": ["a.*.com"]}}, {"web_filter": {"allowed": ["x.com"] * 10001}}):
        with pytest.raises(ValueError):
            validate_policy(bad)
