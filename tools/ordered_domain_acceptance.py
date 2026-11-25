"""Inert ordered-domain acceptance plans for a real API, guest DNS and PostgreSQL runner.

These functions do not publish policies, query DNS, inspect results or claim acceptance.
Category expectations require the synthetic corpus documented in ``build_cases``.
``forwarded`` means the agent must use upstream DNS; upstream availability is checked by
the caller. Events describe persisted rows, including the absence of a row for allow.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from agent.policy import normalize_domain, validate_policy, web_decision


def _rule(domain: str, action: str, kind: str = "simple") -> dict[str, str]:
    return {"domain": domain, "type": kind, "action": action}


def _expect(domain: str, action: str, reason: str = "rule", category: str = "") -> dict[str, Any]:
    return {
        "domain": domain,
        "action": action,
        "dns": "blocked" if action == "block" else "forwarded",
        "event": None if action == "allow" else {
            "action": "blocked" if action == "block" else "monitored",
            "reason": reason, "category": category, "source": "dns",
        },
    }


def _case(key: str, rules: list[dict[str, str]], expectations: list[dict[str, Any]],
          **settings: Any) -> dict[str, Any]:
    return {
        "key": key,
        "policy": validate_policy({"web_filter": {"domain_rules": rules, **settings}}),
        "expectations": expectations,
    }


def build_cases() -> list[dict[str, Any]]:
    """Return eight independent plans with explicit expectations, without any host interaction.

    Publish known synthetic category files before running these cases:
    games includes www.example.net, iana.org and www.iana.org;
    streaming includes www.example.org and www.icann.org;
    shopping includes www.ietf.org and www.icann.org.
    Extra entries must not classify datatracker.ietf.org, used for general monitoring.
    Those memberships were checked against the private web-actions acceptance corpus.

    The caller must record actual policy version/digest and successful guest ACK, query
    guest DNS, then compare newly received event rows after the upload/flush boundary.
    Absence of an immediate event alone does not prove a nonlogging allow decision.
    """
    names = ("ietf.org", "www.ietf.org", "datatracker.ietf.org")
    cases = [
        _case("simple-scope", [_rule("ietf.org", "block")], [
            _expect(names[0], "block"), _expect(names[1], "block"), _expect(names[2], "allow"),
        ]),
        _case("wildcard-scope", [_rule("ietf.org", "block", "wildcard")], [
            _expect(name, "block") for name in names
        ]),
    ]
    for key, first, second in (
        ("allow-before-block", _rule("ietf.org", "allow"), _rule("ietf.org", "block", "wildcard")),
        ("block-before-allow", _rule("ietf.org", "block", "wildcard"), _rule("ietf.org", "allow")),
        ("monitor-before-block", _rule("ietf.org", "monitor"), _rule("ietf.org", "block", "wildcard")),
    ):
        cases.append(_case(key, [first, second], [
            _expect(names[0], first["action"]), _expect(names[1], first["action"]),
            _expect(names[2], "block"),
        ]))
    cases.extend(
        _case(f"{action}-over-blocked-category", [_rule("iana.org", action)], [
            _expect("iana.org", action), _expect("www.iana.org", action),
            _expect("www.example.net", "block", "category", "games"),
        ], category_actions={"games": "block"}, monitor_all=True)
        for action in ("allow", "monitor")
    )
    cases.append(_case("category-fallback", [_rule("example.com", "block")], [
        _expect("www.example.net", "monitor", "category", "games"),
        _expect("www.example.org", "block", "category", "streaming"),
        _expect("www.ietf.org", "allow"),
        _expect("www.icann.org", "block", "category", "streaming"),
        _expect("datatracker.ietf.org", "monitor", "policy"),
    ], category_actions={"games": "monitor", "streaming": "block", "shopping": "allow"}, monitor_all=True))
    return cases


def add_canary(policy: object, domain: object) -> dict[str, Any]:
    """Clone a valid policy and append a simple block rule for a normalized canary name.

    Reject nonempty legacy lists rather than changing their priority while composing an
    ordered table. Reject a canary whose root or www query matches an earlier rule,
    including allow and monitor rules: a swallowed canary cannot prove fresh enforcement.
    Existing category settings are preserved; the appended table rule precedes them.
    """
    name = normalize_domain(domain)
    normalized = validate_policy(policy)
    settings = normalized.setdefault("web_filter", {})
    settings.setdefault("domain_rules", [])
    # The real validator rejects malformed rows and ambiguous legacy/ordered policies.
    normalized = validate_policy(normalized)
    settings = normalized["web_filter"]
    rules = settings["domain_rules"]
    # Mark every prior row as blocking only to detect pattern coverage, regardless of action.
    coverage = {"domain_rules": [{**rule, "action": "block"} for rule in rules]}
    when = datetime(2026, 11, 23, tzinfo=UTC)
    queries = (name,) if name.startswith("www.") else (name, "www." + name)
    if any(web_decision(query, coverage, when)["action"] == "block" for query in queries):
        raise ValueError("canary query is covered by an earlier domain rule")
    rules.append(_rule(name, "block"))
    return validate_policy(normalized)
