"""Agent capabilities a policy needs, matched against the host tags agents report.

Old agents ignore what they do not understand; the panel warns instead of refusing to publish,
so a fleet can be upgraded gradually.
"""

from __future__ import annotations

from typing import Any


def required_tags(body: Any) -> list[str]:
    web_filter = body.get("web_filter") if isinstance(body, dict) else None
    if not isinstance(web_filter, dict):
        return []
    windows = [window for window in web_filter.get("scheduled") or [] if isinstance(window, dict)]
    rules = [*(web_filter.get("blocked") or []), *(web_filter.get("allowed") or []),
             *(rule for window in windows for rule in window.get("blocked") or [])]
    categories = bool(web_filter.get("blocked_categories")) or any(window.get("blocked_categories") for window in windows)
    safe_search = bool(web_filter.get("safe_search"))
    tags = []
    if safe_search or windows:
        tags.append("web-filter:v2")
    if categories:
        tags.append("web-filter:categories")
    # Wildcards, SafeSearch and categories are enforced by the local resolver; hosts mode cannot.
    if categories or safe_search or any(isinstance(rule, str) and rule.startswith("*.") for rule in rules):
        tags.append("web-filter:dns")
    return tags


def missing_tags(body: Any, host_tags: list[str]) -> list[str]:
    return [tag for tag in required_tags(body) if tag not in host_tags]
