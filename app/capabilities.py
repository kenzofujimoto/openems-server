"""Agent capabilities a policy needs, matched against the host tags agents report.

Old agents ignore what they do not understand; the panel warns instead of refusing to publish,
so a fleet can be upgraded gradually.
"""

from __future__ import annotations

from typing import Any


def required_tags(body: Any) -> list[str]:
    tags = []
    if isinstance(body, dict):
        usb = body.get("usb_control")
        apps = body.get("app_control")
        if isinstance(usb, dict) and (usb.get("rules") or usb.get("default_action", "allow") != "allow"):
            tags.append("usb-control:v1")
        if isinstance(apps, dict):
            if apps.get("execution_rules"):
                tags.append("app-control:wdac")
            if apps.get("network_blocked"):
                tags.append("app-control:network")
    web_filter = body.get("web_filter") if isinstance(body, dict) else None
    if not isinstance(web_filter, dict):
        return tags
    windows = [window for window in web_filter.get("scheduled") or [] if isinstance(window, dict)]
    rules = [*(web_filter.get("blocked") or []), *(web_filter.get("allowed") or []),
             *(rule for window in windows for rule in window.get("blocked") or [])]
    categories = bool(web_filter.get("blocked_categories")) or any(window.get("blocked_categories") for window in windows)
    action_maps = [web_filter.get("category_actions"), *(window.get("category_actions") for window in windows)]
    actions = [action for mapping in action_maps if isinstance(mapping, dict) for action in mapping.values()]
    uses_actions = any(isinstance(mapping, dict) and mapping for mapping in action_maps) or web_filter.get("monitor_all") is True
    monitoring = "monitor" in actions or web_filter.get("monitor_all") is True
    # Allow categories also need membership data to suppress global observation.
    categories = categories or bool(actions)
    safe_search = bool(web_filter.get("safe_search"))
    if safe_search or windows:
        tags.append("web-filter:v2")
    if categories:
        tags.append("web-filter:categories")
    if uses_actions:
        tags.append("web-filter:actions")
    if monitoring:
        tags.append("web-filter:monitor")
    # Wildcards, SafeSearch and categories are enforced by the local resolver; hosts mode cannot.
    if categories or monitoring or safe_search or any(isinstance(rule, str) and rule.startswith("*.") for rule in rules):
        tags.append("web-filter:dns")
    return tags


def missing_tags(body: Any, host_tags: list[str]) -> list[str]:
    return [tag for tag in required_tags(body) if tag not in host_tags]
