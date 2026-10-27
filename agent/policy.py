"""Shared dependency-free validation for endpoint policy payloads."""

from __future__ import annotations

import bisect
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
# FortiGuard-style taxonomy over the Universite Toulouse Capitole (UT1) lists; each UT1 list feeds one id.
CATEGORIES: dict[str, dict[str, Any]] = {
    "adult": {"label": "Conteúdo adulto", "group": "Adulto", "sources": ["adult", "mixed_adult", "lingerie"]},
    "dating": {"label": "Relacionamentos", "group": "Adulto", "sources": ["dating"]},
    "gambling": {"label": "Jogos de azar", "group": "Adulto", "sources": ["gambling", "arjel"]},
    "malware": {"label": "Malware", "group": "Segurança", "sources": ["malware", "cryptojacking", "stalkerware"]},
    "phishing": {"label": "Phishing", "group": "Segurança", "sources": ["phishing"]},
    "hacking": {"label": "Hacking", "group": "Segurança", "sources": ["hacking", "ddos"]},
    "proxy": {"label": "VPN e proxies", "group": "Segurança",
              "sources": ["vpn", "residential-proxies", "redirector", "strict_redirector", "strong_redirector"]},
    "drugs": {"label": "Drogas", "group": "Potencialmente ofensivo", "sources": ["drogue"]},
    "violence": {"label": "Violência e ódio", "group": "Potencialmente ofensivo", "sources": ["agressif"]},
    "weapons": {"label": "Materiais perigosos", "group": "Potencialmente ofensivo", "sources": ["dangerous_material"]},
    "warez": {"label": "Pirataria", "group": "Potencialmente ofensivo", "sources": ["warez"]},
    "games": {"label": "Jogos", "group": "Consumo de banda e lazer", "sources": ["games"]},
    "streaming": {"label": "Áudio e vídeo", "group": "Consumo de banda e lazer", "sources": ["audio-video", "radio"]},
    "filehosting": {"label": "Armazenamento e download de arquivos", "group": "Consumo de banda e lazer",
                    "sources": ["filehosting", "download"]},
    "social": {"label": "Redes sociais", "group": "Interesse geral", "sources": ["social_networks"]},
    "chat": {"label": "Chat e mensageiros", "group": "Interesse geral", "sources": ["chat"]},
    "webmail": {"label": "Webmail", "group": "Interesse geral", "sources": ["webmail"]},
    "shopping": {"label": "Compras", "group": "Interesse geral", "sources": ["shopping"]},
    "sports": {"label": "Esportes", "group": "Interesse geral", "sources": ["sports"]},
    "press": {"label": "Notícias", "group": "Interesse geral", "sources": ["press"]},
    "ads": {"label": "Publicidade", "group": "Interesse geral", "sources": ["publicite", "marketingware"]},
    "ai": {"label": "Inteligência artificial", "group": "Negócios e tecnologia", "sources": ["ai"]},
    "bank": {"label": "Bancos", "group": "Negócios e tecnologia", "sources": ["bank"]},
    "financial": {"label": "Serviços financeiros", "group": "Negócios e tecnologia", "sources": ["financial"]},
    "jobsearch": {"label": "Empregos", "group": "Negócios e tecnologia", "sources": ["jobsearch"]},
    "webhosting": {"label": "Hospedagem web", "group": "Negócios e tecnologia", "sources": ["webhosting"]},
    "celebrity": {"label": "Celebridades", "group": "Consumo de banda e lazer", "sources": ["celebrity"]},
}
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


def _validate_categories(value: object) -> list[str]:
    # Membership before set(): unhashable entries must be validation errors, not crashes.
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or item not in CATEGORIES for item in value)
        or len(set(value)) != len(value)
    ):
        raise ValueError("blocked_categories must list distinct known categories")
    return value


def _validate_category_actions(settings: dict[str, Any]) -> None:
    if "category_actions" not in settings:
        return
    actions = settings["category_actions"]
    if (not isinstance(actions, dict) or len(actions) > len(CATEGORIES)
            or any(category not in CATEGORIES or action not in ("allow", "block", "monitor")
                   for category, action in actions.items())):
        raise ValueError("category_actions must map known categories to allow, block or monitor")
    if any(category in actions and actions[category] != "block"
           for category in settings.get("blocked_categories", [])):
        raise ValueError("category action conflicts with legacy blocked_categories")


def _validate_window(value: object) -> dict[str, Any]:
    keys = {"blocked", "blocked_categories", "category_actions", "days", "from", "to"}
    if (
        not isinstance(value, dict)
        or set(value) - keys
        or not {"days", "from", "to"} <= set(value)
        or not {"blocked", "blocked_categories", "category_actions"} & set(value)
    ):
        raise ValueError("schedule window needs days, from, to and blocked rules or categories")
    blocked, days = value.get("blocked", []), value["days"]
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
    if "blocked" in value:
        value["blocked"] = list(dict.fromkeys(normalize_domain_rule(rule) for rule in blocked))
    if "blocked_categories" in value:
        _validate_categories(value["blocked_categories"])
    _validate_category_actions(value)
    return value


def _validate_web_extensions(settings: dict[str, Any]) -> None:
    if "blocked_categories" in settings:
        _validate_categories(settings["blocked_categories"])
    _validate_category_actions(settings)
    if "monitor_all" in settings and type(settings["monitor_all"]) is not bool:
        raise ValueError("monitor_all must be a boolean")
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


def _open_windows(web_filter: dict[str, Any], when: datetime) -> list[dict[str, Any]]:
    windows = web_filter.get("scheduled", [])
    if not windows:
        return []
    local = when.astimezone(ZoneInfo(web_filter["timezone"]))
    day, minute = DAYS[local.weekday()], local.hour * 60 + local.minute
    return [window for window in windows
            if day in window["days"] and _minutes(window["from"]) <= minute < _minutes(window["to"])]


def active_rules(web_filter: dict[str, Any], when: datetime) -> list[str]:
    """Unscheduled rules plus every window active at `when` in the policy timezone."""
    rules = list(web_filter.get("blocked", []))
    for window in _open_windows(web_filter, when):
        rules.extend(window.get("blocked", []))
    return rules


def active_categories(web_filter: dict[str, Any], when: datetime) -> list[str]:
    """Blocked categories active at this instant; monitoring does not imply blocking."""
    return [category for category, action in active_category_actions(web_filter, when).items() if action == "block"]


def active_category_actions(web_filter: dict[str, Any], when: datetime) -> dict[str, str]:
    """Permanent and active-window actions combine without weakening stronger actions."""
    priority = {"allow": 0, "monitor": 1, "block": 2}
    actions: dict[str, str] = {}
    sources = [web_filter, *_open_windows(web_filter, when)]
    for settings in sources:
        for category in settings.get("blocked_categories", []):
            actions[category] = "block"
    selected: dict[str, str] = {}
    for settings in sources:
        for category, action in settings.get("category_actions", {}).items():
            if category not in selected or priority[action] > priority[selected[category]]:
                selected[category] = action
    # Legacy lists retain their historical tie order; JSON object key order is not semantic.
    for category in sorted(selected):
        if category not in actions or priority[selected[category]] > priority[actions[category]]:
            actions[category] = selected[category]
    return actions


def referenced_categories(web_filter: dict[str, Any]) -> list[str]:
    """All categories required for decisions, including explicit allow and monitor."""
    categories: dict[str, None] = {}
    for settings in [web_filter, *web_filter.get("scheduled", [])]:
        for category in [*settings.get("blocked_categories", []), *settings.get("category_actions", {})]:
            categories[category] = None
    return list(categories)


def domain_hash(name: object) -> int:
    """First eight bytes of SHA-256 of the normalized name, big-endian; category files store these."""
    return int.from_bytes(hashlib.sha256(normalize_domain(name).encode("ascii")).digest()[:8], "big")


def in_category(name: object, hashes: list[int]) -> bool:
    """The name or any parent domain (two labels or more) is in the sorted hash list."""
    try:
        labels = normalize_domain(name).split(".")
    except ValueError:
        return False
    for start in range(len(labels) - 1):
        value = domain_hash(".".join(labels[start:]))
        index = bisect.bisect_left(hashes, value)
        if index < len(hashes) and hashes[index] == value:
            return True
    return False


def block_reason(name: object, web_filter: dict[str, Any], when: datetime,
                 categories: dict[str, list[int]] | None = None) -> dict[str, str] | None:
    """Why `name` is blocked at `when`: a rule, else the first active category containing it; None if allowed.

    `web_filter` comes from validate_policy. `categories` maps category ids to sorted hash lists;
    a category without data never blocks.
    """
    decision = web_decision(name, web_filter, when, categories)
    if decision["action"] != "block":
        return None
    reason = {"reason": decision["reason"]}
    if decision["category"] is not None:
        reason["category"] = decision["category"]
    return reason


def web_decision(name: object, web_filter: dict[str, Any], when: datetime,
                 categories: dict[str, list[int]] | None = None) -> dict[str, Any]:
    """Decide a domain action and whether its DNS observation should be recorded."""
    allowed = {"action": "allow", "reason": None, "category": None, "log": False}
    try:
        domain = normalize_domain(name)
    except ValueError:
        return allowed
    if any(_rule_matches(normalize_domain_rule(rule), domain) for rule in web_filter.get("allowed", [])):
        return allowed
    if domain_blocked(domain, active_rules(web_filter, when), []):
        return {"action": "block", "reason": "rule", "category": None, "log": True}
    data = categories or {}
    matched = [(category, action) for category, action in active_category_actions(web_filter, when).items()
               if category in data and in_category(domain, data[category])]
    for action in ("block", "monitor", "allow"):
        category = next((category for category, selected in matched if selected == action), None)
        if category is not None:
            return {"action": action, "reason": "category", "category": category, "log": action != "allow"}
    if web_filter.get("monitor_all", False):
        return {"action": "monitor", "reason": "observation", "category": None, "log": True}
    return allowed


def domain_blocked_at(name: object, web_filter: dict[str, Any], when: datetime,
                      categories: dict[str, list[int]] | None = None) -> bool:
    """Decision at an aware instant; see block_reason."""
    return block_reason(name, web_filter, when, categories) is not None


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


def _control_text(value: object, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or value != value.strip():
        raise ValueError("control selector must be a bounded nonempty string")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("control selector contains control characters")
    return value


def _absolute_application_path(value: object) -> str:
    path = _control_text(value, 2048)
    if not (re.match(r"^[A-Za-z]:[\\/]", path) or (path.startswith("/") and not path.startswith("//"))):
        raise ValueError("application path must be absolute and local")
    if any(part in (".", "..") for part in re.split(r"[\\/]", path)) or any(character in path for character in '*?"<>|%'):
        raise ValueError("application paths must be exact without traversal or expansion")
    return path


def _control_rules(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 256 or any(not isinstance(rule, dict) for rule in value):
        raise ValueError("control rules must be a list of at most 256 objects")
    ids = []
    for rule in value:
        identifier = rule.get("id")
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", identifier):
            raise ValueError("control rule needs an id of at most 64 letters, digits, underscores or hyphens")
        ids.append(identifier)
    if len(set(ids)) != len(ids):
        raise ValueError("control rule ids must be unique")
    return value


def _validate_usb(settings: object) -> None:
    if not isinstance(settings, dict) or set(settings) - {"default_action", "rules"}:
        raise ValueError("usb_control must contain only default_action and rules")
    settings.setdefault("default_action", "allow")
    settings.setdefault("rules", [])
    if settings["default_action"] not in ("allow", "block", "read_only"):
        raise ValueError("unknown USB default action")
    for rule in _control_rules(settings["rules"]):
        selectors = {"class", "vid", "pid", "serial", "instance_id"}
        if set(rule) - {"id", "action", *selectors} or not selectors.intersection(rule):
            raise ValueError("USB rule needs a supported device selector")
        if rule.get("action") not in ("allow", "block", "read_only"):
            raise ValueError("unknown USB action")
        if "class" in rule and rule["class"] != "storage":
            raise ValueError("USB enforcement is restricted to storage; HID devices are protected")
        for field in ("vid", "pid"):
            if field in rule:
                if not isinstance(rule[field], str) or not re.fullmatch(r"[a-fA-F0-9]{4}", rule[field]):
                    raise ValueError("USB VID and PID must each contain four hexadecimal digits")
                rule[field] = rule[field].lower()
        for field in ("serial", "instance_id"):
            if field in rule:
                _control_text(rule[field], 512)


def _validate_app_extensions(settings: dict[str, Any]) -> None:
    if "execution_rules" in settings:
        for rule in _control_rules(settings["execution_rules"]):
            if set(rule) - {"id", "kind", "value", "sample_path"}:
                raise ValueError("unsupported application rule field")
            kind = rule.get("kind")
            value = _control_text(rule.get("value"), 2048)
            if kind == "hash":
                if not re.fullmatch(r"[a-fA-F0-9]{64}", value):
                    raise ValueError("application hash must be a SHA-256 digest")
                rule["value"] = value.lower()
            elif kind == "name":
                rule["value"] = normalize_process(value)
            elif kind == "path":
                _absolute_application_path(value)
            elif kind != "publisher":
                raise ValueError("unknown application rule kind")
            if "sample_path" in rule:
                _absolute_application_path(rule["sample_path"])
    if "network_blocked" in settings:
        paths = settings["network_blocked"]
        if not isinstance(paths, list) or len(paths) > 256:
            raise ValueError("network_blocked must be a list of at most 256 application paths")
        settings["network_blocked"] = list(dict.fromkeys(_absolute_application_path(path) for path in paths))


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
    if isinstance(normalized.get("app_control"), dict):
        _validate_app_extensions(normalized["app_control"])
    if "usb_control" in normalized:
        _validate_usb(normalized["usb_control"])
    return normalized
