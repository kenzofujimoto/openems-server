"""Ordered DNS exceptions preserve first-match semantics and authenticated delivery."""

from datetime import UTC, datetime

import pytest

from agent import policy
from app.capabilities import required_tags
from app.events import InMemoryEventStore
from tests.test_block_log_panel import panel

NOW = datetime(2026, 10, 26, 12, tzinfo=UTC)


def rule(domain="example.net", action="block", kind="simple"):
    return {"domain": domain, "type": kind, "action": action}


def decision(rules, name="example.net", **settings):
    web = policy.validate_policy({"web_filter": {"domain_rules": rules, **settings}})["web_filter"]
    return policy.web_decision(name, web, NOW)


@pytest.mark.parametrize("first,second", [("block", "allow"), ("allow", "block"), ("monitor", "block")])
def test_first_matching_rule_wins_instead_of_action_precedence(first, second):
    result = decision([rule(action=first), rule(action=second, kind="wildcard")])
    assert result == {"action": first, "reason": None if first == "allow" else "rule",
                      "category": None, "log": first != "allow"}


@pytest.mark.parametrize("kind,name,expected", [
    ("simple", "example.net", "block"), ("simple", "www.example.net", "block"),
    ("simple", "a.example.net", "allow"), ("wildcard", "example.net", "block"),
    ("wildcard", "a.b.example.net", "block"), ("wildcard", "otherexample.net", "allow"),
])
def test_domain_match_scope_keeps_legacy_www_and_root_semantics(kind, name, expected):
    assert decision([rule(kind=kind)], name)["action"] == expected


def test_ordered_exceptions_override_schedule_and_unmatched_names_fall_through():
    scheduled = [{"days": ["mon"], "from": "08:00", "to": "18:00", "blocked": ["*.example.net"]}]
    assert decision([rule(action="monitor")], timezone="UTC", scheduled=scheduled)["action"] == "monitor"
    assert decision([rule(action="allow")], "a.example.net", timezone="UTC", scheduled=scheduled)["action"] == "block"


def test_normalization_preserves_rule_order_and_digest_depends_on_order():
    rules = [rule("BÜCHER.de", "monitor", "wildcard"), rule("example.net", "allow")]
    body = policy.validate_policy({"web_filter": {"domain_rules": rules}})
    assert body["web_filter"]["domain_rules"][0]["domain"] == "xn--bcher-kva.de"
    reverse = policy.validate_policy({"web_filter": {"domain_rules": list(reversed(rules))}})
    assert policy.policy_digest(body) != policy.policy_digest(reverse)


@pytest.mark.parametrize("rules", [None, {}, "example.net", [None], [rule(kind="regex")],
    [rule(action="log")], [rule("*.example.net")], [rule("https://example.net")],
    [rule("127.0.0.1")], [{**rule(), "enabled": True}], [rule(), rule()],
    [rule(), rule(action="allow")], [rule()] * 10001,
])
def test_invalid_or_duplicate_rows_are_rejected(rules):
    with pytest.raises(ValueError):
        policy.validate_policy({"web_filter": {"domain_rules": rules}})


@pytest.mark.parametrize("legacy", [{"blocked": ["old.example"]}, {"allowed": ["old.example"]}])
def test_ambiguous_mix_with_nonempty_legacy_lists_is_rejected(legacy):
    with pytest.raises(ValueError):
        policy.validate_policy({"web_filter": {"domain_rules": [rule()], **legacy}})


def test_new_rules_require_dns_and_versioned_capability_without_category_data():
    tags = required_tags({"web_filter": {"domain_rules": [rule(action="monitor")]}})
    assert {"web-filter:domain-rules:v1", "web-filter:actions", "web-filter:monitor", "web-filter:dns"} <= set(tags)
    assert "web-filter:categories" not in tags


def test_old_agents_cannot_fetch_or_ack_ordered_rules_even_if_they_support_category_actions():
    client, administrator = panel(InMemoryEventStore())
    device = client.post("/fct/api/public/v1/register/", json={"devid": "old-domain-agent"}).json()
    auth = {"Authorization": f"Bearer {device['device_token']}"}
    tags = ["web-filter:actions", "web-filter:dns", "web-filter:monitor"]
    payload = {"client_id": device["client_id"], "tags": tags}
    assert client.post("/fct/api/public/v1/host_tags/", headers=auth, json=payload).status_code == 200
    published = client.post("/api/v1/profiles/Default", headers=administrator,
                            json={"web_filter": {"domain_rules": [rule()]}}).json()
    assert "version" in published
    params = {"client_id": device["client_id"]}
    ack = {**params, "version": published["version"], "vdom": "Default", "digest": published["digest"], "success": True}
    assert client.get("/fct/api/public/v1/config/assigned/", headers=auth, params=params).status_code == 409
    assert client.post("/fct/api/public/v1/config/ack/", headers=auth, json=ack).status_code == 409
    tags.append("web-filter:domain-rules:v1")
    assert client.post("/fct/api/public/v1/host_tags/", headers=auth, json=payload).status_code == 200
    assert client.get("/fct/api/public/v1/config/assigned/", headers=auth, params=params).status_code == 200
    assert client.post("/fct/api/public/v1/config/ack/", headers=auth, json=ack).status_code == 200
