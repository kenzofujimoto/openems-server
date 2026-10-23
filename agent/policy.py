"""Shared dependency-free validation for endpoint policy payloads."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any


def policy_digest(body: dict[str, Any]) -> str:
    encoded = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def normalize_domain(value: object) -> str:
    if not isinstance(value, str) or not value or any(c.isspace() for c in value):
        raise ValueError(
            "blocked domain must be a nonempty hostname without whitespace"
        )
    if any(c in value for c in "*/\\:@?#%") or value.endswith("."):
        raise ValueError(
            "URLs, wildcards, addresses and paths are not supported domains"
        )
    try:
        domain = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("invalid IDNA hostname") from exc
    labels = domain.split(".")
    if (
        len(domain) > 253
        or len(labels) < 2
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in labels
        )
    ):
        raise ValueError("invalid hostname")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError("IP addresses are not supported domains")


def normalize_domain_rule(value: object) -> str:
    """Exact domain, or a leading wildcard covering the domain and every subdomain."""
    if isinstance(value, str) and value.startswith("*."):
        return "*." + normalize_domain(value[2:])
    return normalize_domain(value)


def _rule_matches(rule: str, name: str) -> bool:
    if rule.startswith("*."):
        base = rule[2:]
        return name == base or name.endswith("." + base)
    return name == rule or (not rule.startswith("www.") and name == "www." + rule)


def domain_blocked(name: object, blocked: list[str], allowed: list[str]) -> bool:
    """Shared decision for the DNS resolver and the block page; allowed rules win."""
    try:
        domain = normalize_domain(name)
    except ValueError:
        return False
    if not any(_rule_matches(normalize_domain_rule(rule), domain) for rule in blocked):
        return False
    return not any(_rule_matches(normalize_domain_rule(rule), domain) for rule in allowed)


def hosts_names(blocked: list[str], allowed: list[str]) -> list[str]:
    """Names a hosts file can hold: wildcards degrade to the domain and its www name."""
    names: dict[str, None] = {}
    for value in blocked:
        rule = normalize_domain_rule(value)
        base = rule.removeprefix("*.")
        for name in (base,) if base.startswith("www.") else (base, "www." + base):
            if domain_blocked(name, blocked, allowed):
                names[name] = None
    return list(names)


def normalize_process(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9_][A-Za-z0-9_. -]{0,253}", value
    ):
        raise ValueError("blocked application must be an exact executable image name")
    if value != value.strip() or ".." in value or value.endswith("."):
        raise ValueError("invalid executable image name")
    return value.lower()


def validate_policy(body: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise ValueError("policy body must be an object")  # noqa: TRY004 - shared API validation contract
    try:
        normalized = json.loads(json.dumps(body, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise ValueError("policy must contain JSON values") from exc
    for section, key, validator in (
        ("web_filter", "blocked", normalize_domain_rule),
        ("web_filter", "allowed", normalize_domain_rule),
        ("app_control", "blocked", normalize_process),
    ):
        if section not in normalized:
            continue
        settings = normalized[section]
        if not isinstance(settings, dict) or not isinstance(
            settings.get(key, []), list
        ):
            raise ValueError(f"{section}.{key} must be a list")  # noqa: TRY004 - shared API validation contract
        # "blocked" is always materialized; "allowed" only when the policy sets it.
        if key != "blocked" and key not in settings:
            continue
        if len(settings.get(key, [])) > 10000:
            raise ValueError("policy list exceeds 10000 entries")
        settings[key] = list(
            dict.fromkeys(validator(item) for item in settings.get(key, []))
        )
    return normalized
