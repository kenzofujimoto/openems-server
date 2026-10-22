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
    for section, validator in (
        ("web_filter", normalize_domain),
        ("app_control", normalize_process),
    ):
        if section not in normalized:
            continue
        settings = normalized[section]
        if not isinstance(settings, dict) or not isinstance(
            settings.get("blocked", []), list
        ):
            raise ValueError(f"{section}.blocked must be a list")  # noqa: TRY004 - shared API validation contract
        if len(settings.get("blocked", [])) > 10000:
            raise ValueError("policy list exceeds 10000 entries")
        settings["blocked"] = list(
            dict.fromkeys(validator(item) for item in settings.get("blocked", []))
        )
    return normalized
