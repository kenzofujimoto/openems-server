"""Tests for group-assignment rule evaluation and its wiring into EmsService."""

from __future__ import annotations

from app.models import AssignmentRule, Condition, Endpoint, RegisterRequest
from app.rules import evaluate_rules, match_condition
from app.service import EmsService


def _ep(**kw) -> Endpoint:
    base = dict(devid="DEV-1", client_id="cid-1", os="", hostname="", fctver="", vdom="Default")
    base.update(kw)
    return Endpoint(**base)


# --- condition matching -------------------------------------------------

def test_equals_contains_in_operators() -> None:
    ep = _ep(os="Windows 11", hostname="PC-FIN-07", vdom="Default")
    assert match_condition(ep, Condition("os", "contains", "Windows"))
    assert match_condition(ep, Condition("vdom", "equals", "Default"))
    assert match_condition(ep, Condition("hostname", "in", ["PC-FIN-07", "PC-FIN-08"]))
    assert not match_condition(ep, Condition("os", "equals", "Linux"))


def test_host_tag_operator() -> None:
    ep = _ep(host_tags=["compliant", "vpn"])
    assert match_condition(ep, Condition("host_tag", "has_tag", "compliant"))
    assert not match_condition(ep, Condition("host_tag", "has_tag", "quarantine"))


def test_unknown_operator_never_matches() -> None:
    assert not match_condition(_ep(os="X"), Condition("os", "wat", "X"))


# --- rule engine --------------------------------------------------------

def test_priority_decides_winner() -> None:
    ep = _ep(os="Windows 11")
    low = AssignmentRule(id="low", target_vdom="A", priority=200,
                         conditions=[Condition("os", "contains", "Windows")])
    high = AssignmentRule(id="high", target_vdom="B", priority=10,
                          conditions=[Condition("os", "contains", "Windows")])
    assert evaluate_rules(ep, [low, high]) == "B"


def test_no_match_returns_none() -> None:
    ep = _ep(os="Linux")
    rule = AssignmentRule(id="r", target_vdom="A",
                          conditions=[Condition("os", "contains", "Windows")])
    assert evaluate_rules(ep, [rule]) is None


def test_disabled_rule_skipped() -> None:
    ep = _ep(os="Windows")
    rule = AssignmentRule(id="r", target_vdom="A", enabled=False,
                          conditions=[Condition("os", "contains", "Windows")])
    assert evaluate_rules(ep, [rule]) is None


def test_all_conditions_must_match() -> None:
    ep = _ep(os="Windows", hostname="SERVER-1")
    rule = AssignmentRule(id="r", target_vdom="A", conditions=[
        Condition("os", "contains", "Windows"),
        Condition("hostname", "contains", "FIN"),
    ])
    assert evaluate_rules(ep, [rule]) is None  # hostname does not match


# --- service integration ------------------------------------------------

def test_effective_vdom_follows_rule() -> None:
    svc = EmsService()
    ep = svc.register(RegisterRequest(devid="DEV-1", os="Windows 11", vdom="Default"))
    svc.add_rule(AssignmentRule(id="win", target_vdom="Strict",
                                conditions=[Condition("os", "contains", "Windows")]))
    assert svc.effective_vdom(svc.list_endpoints()[0]) == "Strict"
    # unrelated endpoint keeps its own vdom
    assert svc.effective_vdom(_ep(os="macOS", vdom="Default")) == "Default"
    assert ep.client_id  # (ep registered)


def test_config_push_targets_effective_vdom() -> None:
    svc = EmsService()
    ep = svc.register(RegisterRequest(devid="DEV-1", os="Windows 11", vdom="Default"))
    svc.add_rule(AssignmentRule(id="win", target_vdom="Strict",
                                conditions=[Condition("os", "contains", "Windows")]))
    # publishing the Strict profile must notify this endpoint even though it
    # registered under "Default", because a rule assigns it to "Strict".
    svc.set_profile("Strict", {"firewall": "on"})
    msgs = svc.pull_messages(ep.client_id)
    assert msgs == [{"type": "config_update", "vdom": "Strict", "version": 1}]


def test_effective_profile_resolves_via_rule() -> None:
    svc = EmsService()
    ep = svc.register(RegisterRequest(devid="DEV-1", os="Windows 11", vdom="Default"))
    svc.add_rule(AssignmentRule(id="win", target_vdom="Strict",
                                conditions=[Condition("os", "contains", "Windows")]))
    svc.set_profile("Strict", {"firewall": "on"})
    profile = svc.effective_profile(ep.client_id)
    assert profile is not None and profile.vdom == "Strict" and profile.body == {"firewall": "on"}
