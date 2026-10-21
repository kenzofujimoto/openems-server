"""Group-assignment rule evaluation (SPEC-INTEROP.md §3 — group_assignment_rule).

Given an endpoint and a set of rules, pick the target vdom/profile. Rules are
evaluated by ascending priority; the first enabled rule whose conditions all
match (logical AND) wins. If none match, the caller falls back to the endpoint's
own vdom.
"""

from __future__ import annotations

from typing import Optional

from .models import AssignmentRule, Condition, Endpoint


def _attr(endpoint: Endpoint, field: str) -> str:
    return {
        "os": endpoint.os,
        "hostname": endpoint.hostname,
        "fctver": endpoint.fctver,
        "vdom": endpoint.vdom,
    }.get(field, "")


def match_condition(endpoint: Endpoint, condition: Condition) -> bool:
    if condition.field == "host_tag":
        # has_tag: the tag value must be present on the endpoint
        return condition.value in endpoint.host_tags

    actual = _attr(endpoint, condition.field)
    op, value = condition.op, condition.value
    if op == "equals":
        return actual == value
    if op == "contains":
        return isinstance(value, str) and value.lower() in actual.lower()
    if op == "in":
        return actual in value
    return False  # unknown operator never matches (fail closed)


def match_rule(endpoint: Endpoint, rule: AssignmentRule) -> bool:
    return rule.enabled and all(
        match_condition(endpoint, c) for c in rule.conditions
    )


def evaluate_rules(
    endpoint: Endpoint, rules: list[AssignmentRule]
) -> Optional[str]:
    """Return the target vdom of the highest-priority matching rule, or None."""
    for rule in sorted(rules, key=lambda r: r.priority):
        if match_rule(endpoint, rule):
            return rule.target_vdom
    return None
