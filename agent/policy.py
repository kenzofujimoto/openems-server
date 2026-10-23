"""Shared dependency-free validation for endpoint policy payloads."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

# Published at https://www.google.com/supported_domains (187 entries, read 2026-10-23).
GOOGLE_DOMAINS: tuple[str, ...] = (
    "google.com", "google.ad", "google.ae", "google.com.af", "google.com.ag",
    "google.al", "google.am", "google.co.ao", "google.com.ar", "google.as",
    "google.at", "google.com.au", "google.az", "google.ba", "google.com.bd",
    "google.be", "google.bf", "google.bg", "google.com.bh", "google.bi",
    "google.bj", "google.com.bn", "google.com.bo", "google.com.br", "google.bs",
    "google.bt", "google.co.bw", "google.by", "google.com.bz", "google.ca",
    "google.cd", "google.cf", "google.cg", "google.ch", "google.ci", "google.co.ck",
    "google.cl", "google.cm", "google.cn", "google.com.co", "google.co.cr",
    "google.com.cu", "google.cv", "google.com.cy", "google.cz", "google.de",
    "google.dj", "google.dk", "google.dm", "google.com.do", "google.dz",
    "google.com.ec", "google.ee", "google.com.eg", "google.es", "google.com.et",
    "google.fi", "google.com.fj", "google.fm", "google.fr", "google.ga",
    "google.ge", "google.gg", "google.com.gh", "google.com.gi", "google.gl",
    "google.gm", "google.gr", "google.com.gt", "google.gy", "google.com.hk",
    "google.hn", "google.hr", "google.ht", "google.hu", "google.co.id", "google.ie",
    "google.co.il", "google.im", "google.co.in", "google.iq", "google.is",
    "google.it", "google.je", "google.com.jm", "google.jo", "google.co.jp",
    "google.co.ke", "google.com.kh", "google.ki", "google.kg", "google.co.kr",
    "google.com.kw", "google.kz", "google.la", "google.com.lb", "google.li",
    "google.lk", "google.co.ls", "google.lt", "google.lu", "google.lv",
    "google.com.ly", "google.co.ma", "google.md", "google.me", "google.mg",
    "google.mk", "google.ml", "google.com.mm", "google.mn", "google.com.mt",
    "google.mu", "google.mv", "google.mw", "google.com.mx", "google.com.my",
    "google.co.mz", "google.com.na", "google.com.ng", "google.com.ni", "google.ne",
    "google.nl", "google.no", "google.com.np", "google.nr", "google.nu",
    "google.co.nz", "google.com.om", "google.com.pa", "google.com.pe",
    "google.com.pg", "google.com.ph", "google.com.pk", "google.pl", "google.pn",
    "google.com.pr", "google.ps", "google.pt", "google.com.py", "google.com.qa",
    "google.ro", "google.ru", "google.rw", "google.com.sa", "google.com.sb",
    "google.sc", "google.se", "google.com.sg", "google.sh", "google.si",
    "google.sk", "google.com.sl", "google.sn", "google.so", "google.sm",
    "google.sr", "google.st", "google.com.sv", "google.td", "google.tg",
    "google.co.th", "google.com.tj", "google.tl", "google.tm", "google.tn",
    "google.to", "google.com.tr", "google.tt", "google.com.tw", "google.co.tz",
    "google.com.ua", "google.co.ug", "google.co.uk", "google.com.uy",
    "google.co.uz", "google.com.vc", "google.co.ve", "google.co.vi",
    "google.com.vn", "google.vu", "google.ws", "google.rs", "google.co.za",
    "google.co.zm", "google.co.zw", "google.cat",
)
YOUTUBE_NAMES = (
    "www.youtube.com", "m.youtube.com", "youtubei.googleapis.com",
    "youtube.googleapis.com", "www.youtube-nocookie.com",
)
SAFE_SEARCH_ENGINES = ("google", "bing", "youtube", "duckduckgo")
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_CLOCK = re.compile(r"([01][0-9]|2[0-3]):[0-5][0-9]")
_ZONE = re.compile(r"[A-Za-z][A-Za-z0-9_+-]*(?:/[A-Za-z0-9_+-]+)*")


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


def _minutes(clock: str) -> int:
    return int(clock[:2]) * 60 + int(clock[3:])


def _validate_safe_search(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - {"engines", "youtube"}:
        raise ValueError("safe_search must be an object with engines and youtube")
    engines = value.get("engines", [])
    # Membership before set(): unhashable entries must be validation errors, not crashes.
    if (
        not isinstance(engines, list)
        or any(engine not in SAFE_SEARCH_ENGINES for engine in engines)
        or len(set(engines)) != len(engines)
    ):
        raise ValueError("safe_search.engines must list distinct supported engines")
    if value.get("youtube", "strict") not in ("strict", "moderate"):
        raise ValueError("safe_search.youtube must be strict or moderate")
    return value


def _validate_timezone(value: object) -> str:
    if not isinstance(value, str) or not _ZONE.fullmatch(value):
        raise ValueError("timezone must be an IANA zone name")
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError("unknown timezone") from exc
    return value


def _validate_window(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"blocked", "days", "from", "to"}:
        raise ValueError("schedule window needs exactly blocked, days, from and to")
    blocked, days = value["blocked"], value["days"]
    if not isinstance(blocked, list) or len(blocked) > 10000:
        raise ValueError("schedule window blocked must be a list of at most 10000 rules")
    if (
        not isinstance(days, list)
        or not days
        or any(day not in DAYS for day in days)
        or len(set(days)) != len(days)
    ):
        raise ValueError("schedule window days must list distinct weekdays")
    start, end = value["from"], value["to"]
    if not all(isinstance(clock, str) and _CLOCK.fullmatch(clock) for clock in (start, end)):
        raise ValueError("schedule window times must be HH:MM")
    if _minutes(start) >= _minutes(end):
        raise ValueError("schedule window must start before it ends; split windows across midnight")
    value["blocked"] = list(dict.fromkeys(normalize_domain_rule(rule) for rule in blocked))
    return value


def _validate_web_extensions(settings: dict[str, Any]) -> None:
    if "safe_search" in settings:
        _validate_safe_search(settings["safe_search"])
    if "timezone" in settings:
        _validate_timezone(settings["timezone"])
    if "scheduled" in settings:
        windows = settings["scheduled"]
        if not isinstance(windows, list) or len(windows) > 50:
            raise ValueError("scheduled must be a list of at most 50 windows")
        if windows and "timezone" not in settings:
            raise ValueError("scheduled rules require a timezone")
        settings["scheduled"] = [_validate_window(window) for window in windows]


def active_rules(web_filter: dict[str, Any], when: datetime) -> list[str]:
    """Unscheduled rules plus every window active at `when` in the policy timezone."""
    rules = list(web_filter.get("blocked", []))
    windows = web_filter.get("scheduled", [])
    if windows:
        local = when.astimezone(ZoneInfo(web_filter["timezone"]))
        day, minute = DAYS[local.weekday()], local.hour * 60 + local.minute
        for window in windows:
            if day in window["days"] and _minutes(window["from"]) <= minute < _minutes(window["to"]):
                rules.extend(window["blocked"])
    return rules


def domain_blocked_at(name: object, web_filter: dict[str, Any], when: datetime) -> bool:
    """Decision at an aware instant; `web_filter` comes from validate_policy."""
    return domain_blocked(name, active_rules(web_filter, when), web_filter.get("allowed", []))


def hosts_names_at(web_filter: dict[str, Any], when: datetime) -> list[str]:
    return hosts_names(active_rules(web_filter, when), web_filter.get("allowed", []))


def safe_search_target(name: object, web_filter: dict[str, Any]) -> str | None:
    """Enforced SafeSearch host for a search engine name, or None."""
    settings = web_filter.get("safe_search") or {}
    engines = settings.get("engines", [])
    try:
        domain = normalize_domain(name)
    except ValueError:
        return None
    if "google" in engines and domain.removeprefix("www.") in GOOGLE_DOMAINS:
        return "forcesafesearch.google.com"
    if "youtube" in engines and domain in YOUTUBE_NAMES:
        return "restrict.youtube.com" if settings.get("youtube", "strict") == "strict" else "restrictmoderate.youtube.com"
    if "bing" in engines and domain == "www.bing.com":
        return "strict.bing.com"
    if "duckduckgo" in engines and domain in ("duckduckgo.com", "www.duckduckgo.com"):
        return "safe.duckduckgo.com"
    return None


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
    if isinstance(normalized.get("web_filter"), dict):
        _validate_web_extensions(normalized["web_filter"])
    return normalized
