"""Policy actions preserve blocking semantics and explicit observation choices."""

from datetime import UTC, datetime

import pytest

from agent import policy
from agent.categories import build_category_file, parse_category_file

NOW = datetime(2026, 10, 26, 12, tzinfo=UTC)
NIGHT = datetime(2026, 10, 26, 20, tzinfo=UTC)


def settings(**values):
    return policy.validate_policy({"web_filter": values})["web_filter"]


def category_data(**values):
    return {category: parse_category_file(build_category_file(domains)) for category, domains in values.items()}


def decide(name="watch.example", when=NOW, categories=None, **values):
    return policy.web_decision(name, settings(**values), when, categories)


@pytest.mark.parametrize("action,logged", [("allow", False), ("monitor", True), ("block", True)])
def test_three_actions_select_behavior_and_log(action, logged):
    data = category_data(streaming=["watch.example"])
    assert decide(categories=data, category_actions={"streaming": action}) == {
        "action": action, "reason": "category", "category": "streaming", "log": logged,
    }


def test_explicit_domain_exception_wins_rules_categories_schedules_and_global_monitoring():
    web = dict(blocked=["*.watch.example"], allowed=["*.watch.example"], monitor_all=True,
               category_actions={"streaming": "block"}, timezone="UTC",
               scheduled=[{"days": ["mon"], "from": "08:00", "to": "18:00",
                           "category_actions": {"streaming": "block"}}])
    assert decide(name="api.watch.example", categories=category_data(streaming=["watch.example"]), **web) == {
        "action": "allow", "reason": None, "category": None, "log": False,
    }


def test_overlap_uses_block_then_monitor_then_allow_independent_of_map_order():
    data = category_data(streaming=["watch.example"], games=["watch.example"], adult=["watch.example"])
    assert decide(categories=data, category_actions={"streaming": "allow", "games": "monitor"})["action"] == "monitor"
    assert decide(categories=data, category_actions={"streaming": "monitor", "adult": "block"}) == {
        "action": "block", "reason": "category", "category": "adult", "log": True,
    }
    assert decide(categories=data, category_actions={"adult": "block", "streaming": "monitor"})["action"] == "block"


def test_explicit_rule_still_blocks_when_category_allows():
    assert decide(blocked=["watch.example"], categories=category_data(streaming=["watch.example"]),
                  category_actions={"streaming": "allow"}) == {
        "action": "block", "reason": "rule", "category": None, "log": True,
    }


def test_default_allow_global_monitor_and_explicit_category_allow_are_distinct():
    assert decide() == {"action": "allow", "reason": None, "category": None, "log": False}
    assert decide(monitor_all=True) == {"action": "monitor", "reason": "observation", "category": None, "log": True}
    assert decide(monitor_all=True, category_actions={"streaming": "allow"},
                  categories=category_data(streaming=["watch.example"])) == {
        "action": "allow", "reason": "category", "category": "streaming", "log": False,
    }
    assert decide(name="not a domain", monitor_all=True)["log"] is False


def test_missing_category_data_does_not_invent_membership_or_block():
    assert decide(category_actions={"streaming": "block"})["action"] == "allow"
    assert decide(category_actions={"streaming": "monitor"}, categories={})["log"] is False
    assert decide(category_actions={"streaming": "block"}, monitor_all=True)["category"] is None


def test_active_schedules_combine_with_permanent_actions_without_weakening_them():
    web = settings(category_actions={"streaming": "monitor"}, timezone="UTC", scheduled=[
        {"days": ["mon"], "from": "08:00", "to": "18:00", "category_actions": {"streaming": "block"}},
        {"days": ["mon"], "from": "08:00", "to": "18:00", "category_actions": {"streaming": "allow"}},
    ])
    data = category_data(streaming=["watch.example"])
    assert policy.web_decision("watch.example", web, NOW, data)["action"] == "block"
    assert policy.web_decision("watch.example", web, NIGHT, data)["action"] == "monitor"
    assert policy.active_categories(web, NOW) == ["streaming"]
    assert policy.active_categories(web, NIGHT) == []
    assert policy.referenced_categories(web) == ["streaming"]


def test_legacy_categories_keep_reason_and_collect_monitored_downloads():
    web = settings(blocked_categories=["games"], category_actions={"streaming": "monitor", "adult": "allow"})
    data = category_data(games=["play.example"], streaming=["watch.example"])
    assert policy.block_reason("play.example", web, NOW, data) == {"reason": "category", "category": "games"}
    assert policy.block_reason("watch.example", web, NOW, data) is None
    assert policy.referenced_categories(web) == ["games", "streaming", "adult"]


@pytest.mark.parametrize("values", [
    {"category_actions": []}, {"category_actions": {"unknown": "block"}},
    {"category_actions": {"streaming": "deny"}}, {"category_actions": {"streaming": True}},
    {"category_actions": {"streaming": []}}, {"monitor_all": 1}, {"monitor_all": "true"},
    {"blocked_categories": ["games"], "category_actions": {"games": "allow"}},
    {"blocked_categories": ["games"], "category_actions": {"games": "monitor"}},
    {"timezone": "UTC", "scheduled": [{"days": ["mon"], "from": "08:00", "to": "18:00",
                                        "category_actions": {"streaming": "bad"}}]},
])
def test_invalid_or_conflicting_actions_are_rejected(values):
    with pytest.raises(ValueError):
        settings(**values)


def test_legacy_and_explicit_same_block_are_not_a_conflict_and_input_is_not_mutated():
    value = {"web_filter": {"blocked_categories": ["games"], "category_actions": {"games": "block"}}}
    before = {"web_filter": {"blocked_categories": ["games"], "category_actions": {"games": "block"}}}
    normalized = policy.validate_policy(value)
    assert normalized["web_filter"]["category_actions"] == {"games": "block"}
    assert value == before
