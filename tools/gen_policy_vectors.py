#!/usr/bin/env python3
"""Generate contract/policy-vectors.json from agent/policy.py.

The native agent must reproduce these digests and normalizations byte for byte.
Regenerate only when policy.py changes on purpose: python tools/gen_policy_vectors.py
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agent"))

from categories import build_category_file, parse_category_file
from policy import (
    CATEGORIES,
    GOOGLE_DOMAINS,
    block_reason,
    domain_blocked,
    domain_blocked_at,
    domain_hash,
    hosts_names,
    normalize_domain,
    normalize_domain_rule,
    normalize_process,
    policy_digest,
    safe_search_target,
    validate_policy,
    web_decision,
)

OUTPUT = ROOT / "contract" / "policy-vectors.json"

BODIES: list[dict[str, Any]] = [
    {},
    {"web_filter": {"blocked": ["example.com"]}},
    {"web_filter": {"blocked": ["facebook.com", "tiktok.com"]}, "app_control": {"blocked": ["utorrent.exe"]}},
    {"b": 1, "a": 2, "B": 3, "aa": [3, 2, 1], "_": None},
    {"unicode": "ação ✓ 日本 😀",
     "escapes": "quote\" backslash\\ newline\n tab\t cr\r bell\u0007 nul\u0000 del\u007f sep "},  # noqa: RUF001 - U+2028 is part of the canonical JSON vector
    {"numbers": [0, -1, 42, 9007199254740993, 0.5, -0.25, 1.0, 100.0, 1e-05, 0.0001, 1e16, 1.5e300, 123456789.123]},
    {"booleans": [True, False], "nested": {"z": {"y": {"x": []}}, "a": {}}},
    {"web_filter": {"blocked": [], "mode": "explicit"},
     "app_control": {"blocked": ["steam.exe", "my app.exe"]}, "version_note": "v2"},
]

DOMAINS = [
    "example.com", "Example.COM", "sub.example.co.uk", "a-b.io", "bücher.de", "xn--bcher-kva.de", "a1.b2",
    "*.example.com", "http://example.com", "example.com/path", "example.com:443", "user@example.com",
    "1.2.3.4", "localhost", "example..com", "-bad.com", "bad-.com", "example.com.", "exa mple.com", "",
    "a" * 64 + ".com", ".".join(["a" * 63] * 4) + ".com", "x%20.com", "ex\\ample.com",
]

DOMAIN_RULES = [
    "example.com", "*.Example.COM", "*.bücher.de", "*.sub.example.co.uk", "*", "*.", "*.com", "a.*.com",
    "**.example.com", "*example.com", "*.example.com.", "*.1.2.3.4", ".example.com", "*.*.example.com", "",
]

# (name, blocked rules, allowed rules): the resolver and the HTTPS page share this decision.
MATCHES = [
    ("example.com", ["example.com"], []), ("WWW.Example.com", ["example.com"], []),
    ("sub.example.com", ["example.com"], []), ("example.com", ["*.example.com"], []),
    ("a.b.example.com", ["*.example.com"], []), ("example.com.br", ["*.example.com"], []),
    ("notexample.com", ["*.example.com"], []), ("docs.google.com", ["*.google.com"], ["mail.google.com"]),
    ("mail.google.com", ["*.google.com"], ["mail.google.com"]), ("www.mail.google.com", ["*.google.com"], ["mail.google.com"]),
    ("a.mail.google.com", ["*.google.com"], ["mail.google.com"]), ("x.example.com", ["*.example.com"], ["*.example.com"]),
    ("www.example.com", ["www.example.com"], []), ("www.www.example.com", ["www.example.com"], []),
    ("bücher.de", ["*.xn--bcher-kva.de"], []), ("not a name", ["*.example.com"], []), ("127.0.0.1", ["example.com"], []),
]

HOSTS = [
    (["*.example.com", "other.org"], []), (["example.com"], ["www.example.com"]),
    (["www.example.com", "*.example.com"], []), (["*.google.com"], ["*.google.com"]), ([], []),
]

WORKDAYS = ["mon", "tue", "wed", "thu", "fri"]
SCHEDULED = {"blocked": ["*.example.com"], "allowed": ["m.example.com"], "timezone": "America/Sao_Paulo",
             "scheduled": [{"blocked": ["*.facebook.com"], "days": WORKDAYS, "from": "08:00", "to": "18:00"},
                           {"blocked": ["games.example.org"], "days": ["sat", "sun"], "from": "00:00", "to": "23:59"}]}
# (name, UTC instant) evaluated against SCHEDULED; 2026-10-26 is a Monday, Sao Paulo is UTC-3.
SCHEDULE_CASES = [
    ("www.facebook.com", "2026-10-26T10:59:00"), ("www.facebook.com", "2026-10-26T11:00:00"),
    ("www.facebook.com", "2026-10-26T20:59:00"), ("www.facebook.com", "2026-10-26T21:00:00"),
    ("www.facebook.com", "2026-10-25T14:00:00"), ("games.example.org", "2026-10-25T14:00:00"),
    ("games.example.org", "2026-10-26T14:00:00"), ("games.example.org", "2026-10-26T02:30:00"),
    ("m.example.com", "2026-10-26T14:00:00"), ("a.example.com", "2026-10-25T03:00:00"),
]
SAFE_SEARCH = {"safe_search": {"engines": ["google", "bing", "youtube", "duckduckgo"]}}
SAFE_SEARCH_CASES = [
    ("www.google.com", SAFE_SEARCH), ("Google.com.BR", SAFE_SEARCH), ("www.google.co.uk", SAFE_SEARCH),
    ("mail.google.com", SAFE_SEARCH), ("forcesafesearch.google.com", SAFE_SEARCH), ("www.youtube.com", SAFE_SEARCH),
    ("youtubei.googleapis.com", SAFE_SEARCH), ("www.bing.com", SAFE_SEARCH), ("bing.com", SAFE_SEARCH),
    ("duckduckgo.com", SAFE_SEARCH), ("example.org", SAFE_SEARCH), ("not a name", SAFE_SEARCH),
    ("m.youtube.com", {"safe_search": {"engines": ["youtube"], "youtube": "moderate"}}),
    ("www.google.com", {"safe_search": {"engines": ["youtube"]}}), ("www.google.com", {}),
]

CATEGORY_FILE_DOMAINS = ["b.example", "a.example", "A.example", "not a domain", "*.bad", "steampowered.com"]
CATEGORY_SETS = {"games": ["steampowered.com", "steamcommunity.com"], "social": ["facebook.com"]}
CATEGORY_FILTER = {"blocked": ["steamcommunity.com"], "blocked_categories": ["games"], "allowed": ["store.steampowered.com"],
                   "timezone": "UTC",
                   "scheduled": [{"blocked_categories": ["social"], "days": ["mon"], "from": "08:00", "to": "18:00"}]}
CATEGORY_CASES = [
    ("api.steampowered.com", "2026-10-26T19:00:00"), ("store.steampowered.com", "2026-10-26T19:00:00"),
    ("steamcommunity.com", "2026-10-25T03:00:00"), ("notsteampowered.com", "2026-10-26T19:00:00"),
    ("www.facebook.com", "2026-10-26T12:00:00"), ("www.facebook.com", "2026-10-26T19:00:00"),
    ("example.org", "2026-10-26T12:00:00"),
]

PROCESSES = [
    "chrome.exe", "Chrome.EXE", "my app.exe", "utorrent", "a_b-c.exe", "../evil.exe", " lead.exe",
    "trail.exe ", "dot.", "", "a/b.exe", "a\\b.exe", "-dash.exe", "x" * 255, "x" * 254,
]

VALIDATE: list[Any] = [
    {"web_filter": {"category_actions": {"games": "allow", "streaming": "monitor", "adult": "block"}, "monitor_all": True}},
    {"web_filter": {"blocked_categories": ["games"], "category_actions": {"games": "block"}}},
    {"web_filter": {"blocked_categories": ["games"], "category_actions": {"games": "monitor"}}},
    {"web_filter": {"blocked_categories": ["games"], "category_actions": {"games": "allow"}}},
    {"web_filter": {"category_actions": {"unknown": "block"}}},
    {"web_filter": {"category_actions": {"games": "deny"}}},
    {"web_filter": {"category_actions": {"games": []}}},
    {"web_filter": {"category_actions": []}},
    {"web_filter": {"monitor_all": "true"}},
    {"web_filter": {"monitor_all": 1}},
    {"web_filter": {"timezone": "UTC", "scheduled": [
        {"days": ["mon"], "from": "08:00", "to": "18:00", "category_actions": {"games": "monitor"}}]}},
    {"usb_control": {}},
    {"usb_control": {"default_action": "block", "rules": [
        {"id": "approved", "action": "allow", "vid": "0781", "pid": "ABCD", "serial": "SN1"},
        {"id": "rest", "action": "read_only", "class": "storage"}]}},
    {"usb_control": {"default_action": "erase"}},
    {"usb_control": {"rules": [{"id": "a", "action": "block"}]}},
    {"usb_control": {"rules": [{"id": "a", "action": "block", "class": "hid"}]}},
    {"usb_control": {"rules": [{"id": "a", "action": "block", "vid": "zzzz"}]}},
    {"usb_control": {"rules": [{"id": "a", "action": "block", "serial": "bad\nserial"}]}},
    {"app_control": {"execution_rules": [
        {"id": "a", "kind": "hash", "value": "AB" * 32, "sample_path": r"C:\Apps\a.exe"},
        {"id": "b", "kind": "name", "value": "Example.EXE"},
        {"id": "c", "kind": "publisher", "value": "Example Publisher"},
        {"id": "catalog-d", "kind": "publisher", "value": "Catalog Vendor", "if_present": True}],
        "network_blocked": [r"C:\Apps\a.exe", r"C:\Apps\a.exe"]}},
    {"app_control": {"execution_rules": [{"id": "a", "kind": "hash", "value": "bad"}]}},
    {"app_control": {"execution_rules": [{"id": "a", "kind": "publisher", "value": "X", "if_present": "yes"}]}},
    {"app_control": {"execution_rules": [{"id": "a", "kind": "name", "value": "../bad.exe"}]}},
    {"app_control": {"execution_rules": [{"id": "a", "kind": "path", "value": "relative.exe"}]}},
    {"app_control": {"network_blocked": [r"\\server\share\app.exe"]}},
    {"web_filter": {"blocked": ["Example.COM", "example.com", "bücher.de"]},
     "app_control": {"blocked": ["A.exe", "a.exe"]}, "other": {"keep": True}},
    {"web_filter": {"blocked": "example.com"}},
    {"web_filter": ["example.com"]},
    {"app_control": {"blocked": ["../x.exe"]}},
    {"web_filter": {"blocked": ["*.Example.com", "*.example.com"], "allowed": ["Mail.example.com"]}},
    {"web_filter": {"allowed": "x.com"}},
    {"web_filter": {"allowed": ["*.com"]}},
    {"web_filter": {"blocked": ["a.*.com"]}},
    {"web_filter": CATEGORY_FILTER},
    {"web_filter": {"blocked_categories": ["altavista"]}},
    {"web_filter": {"blocked_categories": ["games", "games"]}},
    {"web_filter": {"timezone": "UTC", "scheduled": [{"days": ["mon"], "from": "08:00", "to": "18:00"}]}},
    {"web_filter": {"timezone": "UTC", "scheduled": [{"blocked_categories": [1], "days": ["mon"], "from": "08:00", "to": "18:00"}]}},
    {"web_filter": SCHEDULED},
    {"web_filter": {"safe_search": {"engines": ["google", "youtube"], "youtube": "moderate"}}},
    {"web_filter": {"safe_search": {"engines": ["altavista"]}}},
    {"web_filter": {"safe_search": {"engines": ["google", "google"]}}},
    {"web_filter": {"safe_search": {"engines": ["google"], "youtube": "lenient"}}},
    {"web_filter": {"scheduled": SCHEDULED["scheduled"]}},
    {"web_filter": {"timezone": "Mars/Olympus"}},
    {"web_filter": {"timezone": "UTC", "scheduled": [{"blocked": [], "days": ["mon"], "from": "18:00", "to": "08:00"}]}},
    {"web_filter": {"timezone": "UTC", "scheduled": [{"blocked": [], "days": ["mon", "mon"], "from": "08:00", "to": "09:00"}]}},
    {"web_filter": {"timezone": "UTC", "scheduled": [{"blocked": [], "days": ["mon"], "from": "8:00", "to": "09:00"}]}},
    {"web_filter": {"timezone": "UTC", "scheduled": [{"blocked": [], "days": ["mon"], "from": "08:00", "to": "24:00"}]}},
    {"web_filter": {"timezone": "UTC", "scheduled": [{"blocked": [], "days": [], "from": "08:00", "to": "09:00"}]}},
    {"web_filter": {"timezone": "UTC", "scheduled": [{"blocked": [], "days": ["mon"], "from": "08:00", "to": "09:00", "x": 1}]}},
    *({"web_filter": {"domain_rules": rules}} for rules in [
        [], None, {},
        [{"domain": "BÜCHER.de", "type": "wildcard", "action": "monitor"}],
        [{"domain": "example.net", "type": "regex", "action": "block"}],
        [{"domain": "example.net", "type": "simple", "action": "log"}],
        [{"domain": "*.example.net", "type": "wildcard", "action": "block"}],
        [{"domain": "example.net", "type": "simple", "action": "block"}] * 2,
    ]),
]


def _outcome(function: Any, value: Any) -> dict[str, Any]:
    try:
        return {"input": value, "normalized": function(value)}
    except ValueError:
        return {"input": value, "error": True}


def _categories() -> dict[str, Any]:
    data = build_category_file(CATEGORY_FILE_DOMAINS)
    web_filter = validate_policy({"web_filter": CATEGORY_FILTER})["web_filter"]
    sets = {category: parse_category_file(build_category_file(domains)) for category, domains in CATEGORY_SETS.items()}
    return {
        "taxonomy": list(CATEGORIES),
        "labels": {category: entry["label"] for category, entry in CATEGORIES.items()},
        "hashes": [{"domain": domain, "hash": f"{domain_hash(domain):016x}"} for domain in ("steampowered.com", "Example.COM", "bücher.de")],
        "file": {"hex": data.hex(), "sha256": hashlib.sha256(data).hexdigest(),
                 "hashes": [f"{value:016x}" for value in parse_category_file(data)]},
        "decisions": {
            "web_filter": CATEGORY_FILTER, "sets": CATEGORY_SETS,
            "cases": [{"name": name, "when": when,
                       "result": domain_blocked_at(name, web_filter, datetime.fromisoformat(when).replace(tzinfo=UTC), sets),
                       "reason": block_reason(name, web_filter, datetime.fromisoformat(when).replace(tzinfo=UTC), sets)}
                      for name, when in CATEGORY_CASES],
        },
    }


def _web_actions() -> list[dict[str, Any]]:
    sets = {"games": ["watch.example"], "streaming": ["watch.example"], "adult": ["watch.example"]}
    data = {category: parse_category_file(build_category_file(domains)) for category, domains in sets.items()}
    cases = [
        ({}, "watch.example", "2026-10-26T12:00:00"),
        ({"monitor_all": True}, "watch.example", "2026-10-26T12:00:00"),
        ({"monitor_all": True}, "not a domain", "2026-10-26T12:00:00"),
    ]
    cases.extend(({"category_actions": {"streaming": action}}, "watch.example", "2026-10-26T12:00:00")
                 for action in ("allow", "monitor", "block"))
    cases.extend([
        ({"category_actions": {"streaming": "monitor", "games": "monitor"}}, "watch.example", "2026-10-26T12:00:00"),
        ({"category_actions": {"games": "monitor", "streaming": "monitor"}}, "watch.example", "2026-10-26T12:00:00"),
        ({"blocked_categories": ["streaming", "games"]}, "watch.example", "2026-10-26T12:00:00"),
        ({"category_actions": {"adult": "block"}, "timezone": "UTC", "scheduled": [
            {"days": ["mon"], "from": "08:00", "to": "18:00", "blocked_categories": ["streaming", "games"]}]},
         "watch.example", "2026-10-26T12:00:00"),
        ({"category_actions": {"streaming": "allow", "games": "monitor"}}, "watch.example", "2026-10-26T12:00:00"),
        ({"category_actions": {"streaming": "monitor", "adult": "block"}}, "watch.example", "2026-10-26T12:00:00"),
        ({"category_actions": {"streaming": "allow"}, "monitor_all": True}, "watch.example", "2026-10-26T12:00:00"),
        ({"category_actions": {"streaming": "block"}, "allowed": ["*.watch.example"], "monitor_all": True},
         "api.watch.example", "2026-10-26T12:00:00"),
        ({"category_actions": {"streaming": "allow"}, "blocked": ["watch.example"]},
         "watch.example", "2026-10-26T12:00:00"),
        ({"blocked_categories": ["games"], "category_actions": {"streaming": "monitor"}},
         "watch.example", "2026-10-26T12:00:00"),
        ({"category_actions": {"streaming": "monitor"}}, "other.example", "2026-10-26T12:00:00"),
    ])
    scheduled = {"category_actions": {"streaming": "monitor"}, "timezone": "UTC", "scheduled": [
        {"days": ["mon"], "from": "08:00", "to": "18:00", "category_actions": {"streaming": "block"}}]}
    cases.extend((scheduled, "watch.example", when) for when in ("2026-10-26T12:00:00", "2026-10-26T20:00:00"))
    for action in ("allow", "block", "monitor"):
        for kind in ("simple", "wildcard"):
            cases.extend(({"domain_rules": [
                    {"domain": "watch.example", "type": kind, "action": action},
                    {"domain": "watch.example", "type": "wildcard" if kind == "simple" else "simple", "action": "block"},
                ], "category_actions": {"streaming": "block"}}, name, "2026-10-26T12:00:00")
                for name in ("watch.example", "www.watch.example", "api.watch.example", "other.example"))
    return [{"web_filter": raw, "sets": sets, "name": name, "when": when,
             "decision": web_decision(name, validate_policy({"web_filter": raw})["web_filter"],
                                      datetime.fromisoformat(when).replace(tzinfo=UTC), data)}
            for raw, name, when in cases]


def build() -> dict[str, Any]:
    return {
        "_comment": "Generated by tools/gen_policy_vectors.py from agent/policy.py; do not edit by hand.",
        "policies": [
            {
                "body": body,
                "canonical": json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False),
                "digest": policy_digest(body),
            }
            for body in BODIES
        ],
        "domains": [_outcome(normalize_domain, value) for value in DOMAINS],
        "domain_rules": [_outcome(normalize_domain_rule, value) for value in DOMAIN_RULES],
        "matches": [{"name": name, "blocked": blocked, "allowed": allowed, "result": domain_blocked(name, blocked, allowed)}
                    for name, blocked, allowed in MATCHES],
        "schedule": {
            "web_filter": SCHEDULED,
            "cases": [{"name": name, "when": when, "result": domain_blocked_at(
                name, validate_policy({"web_filter": SCHEDULED})["web_filter"], datetime.fromisoformat(when).replace(tzinfo=UTC))}
                for name, when in SCHEDULE_CASES],
        },
        "safe_search": [{"name": name, "web_filter": web, "target": safe_search_target(
            name, validate_policy({"web_filter": web})["web_filter"])} for name, web in SAFE_SEARCH_CASES],
        "google_domains": list(GOOGLE_DOMAINS),
        "categories": _categories(),
        "web_actions": _web_actions(),
        "hosts_names": [{"blocked": blocked, "allowed": allowed, "names": hosts_names(blocked, allowed)}
                        for blocked, allowed in HOSTS],
        "processes": [_outcome(normalize_process, value) for value in PROCESSES],
        "validate": [_outcome(validate_policy, value) for value in VALIDATE],
    }


def render() -> str:
    return json.dumps(build(), ensure_ascii=False, indent=2) + "\n"


def main() -> int:
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(render(), encoding="utf-8", newline="\n")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
