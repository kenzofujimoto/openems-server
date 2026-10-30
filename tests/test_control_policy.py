"""Wire validation for native USB and application controls, shared with Rust vectors."""
from __future__ import annotations

import pytest

from agent.policy import validate_policy
from app.capabilities import missing_tags


def test_usb_rules_normalize_ids_without_reordering_first_match_priority():
    body = {"usb_control": {"default_action": "block", "rules": [
        {"id": "approved", "action": "allow", "vid": "0781", "pid": "ABCD", "serial": "SN1"},
        {"id": "other", "action": "read_only", "class": "storage"},
    ]}}
    normalized = validate_policy(body)
    assert normalized["usb_control"]["rules"][0]["pid"] == "abcd"
    assert [rule["id"] for rule in normalized["usb_control"]["rules"]] == ["approved", "other"]
    assert body["usb_control"]["rules"][0]["pid"] == "ABCD", "validation must not mutate the request"


@pytest.mark.parametrize("settings", [
    {"default_action": "erase"}, {"rules": "block"},
    {"rules": [{"id": "a", "action": "block"}]},
    {"rules": [{"id": "a", "action": "block", "class": "hid"}]},
    {"rules": [{"id": "a", "action": "block", "vid": "zzzz"}]},
    {"rules": [{"id": "a", "action": "block", "instance_id": "bad\ninstance"}]},
    {"rules": [{"id": "a", "action": "allow", "class": "storage"}] * 2},
    {"unknown": True},
])
def test_unsafe_or_ambiguous_usb_settings_are_rejected(settings):
    with pytest.raises(ValueError):
        validate_policy({"usb_control": settings})


def test_application_rules_normalize_hashes_and_keep_legacy_process_rules():
    body = {"app_control": {"blocked": ["Legacy.EXE"], "execution_rules": [
        {"id": "binary", "kind": "hash", "value": "AB" * 32, "sample_path": r"C:\Apps\one.exe"},
        {"id": "publisher", "kind": "publisher", "value": "Example Publisher", "sample_path": r"C:\Apps\two.exe"},
    ], "network_blocked": [r"C:\Apps\three.exe", r"C:\Apps\three.exe"]}}
    normalized = validate_policy(body)["app_control"]
    assert normalized["blocked"] == ["legacy.exe"]
    assert normalized["execution_rules"][0]["value"] == "ab" * 32
    assert normalized["network_blocked"] == [r"C:\Apps\three.exe"]


@pytest.mark.parametrize("settings", [
    {"execution_rules": [{"id": "a", "kind": "hash", "value": "not-a-hash"}]},
    {"execution_rules": [{"id": "a", "kind": "path", "value": "relative.exe"}]},
    {"execution_rules": [{"id": "a", "kind": "name", "value": "../evil.exe"}]},
    {"execution_rules": [{"id": "a", "kind": "publisher", "value": "bad\npublisher"}]},
    {"execution_rules": [{"id": "a", "kind": "hash", "value": "ab" * 32, "sample_path": "relative.exe"}]},
    {"network_blocked": ["relative.exe"]}, {"network_blocked": [r"\\server\share\app.exe"]},
    {"execution_rules": [{"id": "a", "kind": "delete", "value": "app.exe"}]},
])
def test_unsafe_application_rules_are_rejected(settings):
    with pytest.raises(ValueError):
        validate_policy({"app_control": settings})


def test_panel_reports_control_capability_gaps_even_without_a_web_filter():
    body = {"usb_control": {"default_action": "block"}, "app_control": {
        "execution_rules": [{"id": "a", "kind": "hash", "value": "ab" * 32}],
        "network_blocked": [r"C:\Apps\one.exe"],
    }}
    assert set(missing_tags(body, [])) == {"usb-control:v1", "app-control:wdac", "app-control:network"}


def test_catalog_rules_may_apply_only_where_present():
    policy = validate_policy({"app_control": {"execution_rules": [
        {"id": "catalog-1", "kind": "publisher", "value": "CN=Example", "if_present": True}]}})
    assert policy["app_control"]["execution_rules"][0]["if_present"] is True
    with pytest.raises(ValueError, match="if_present"):
        validate_policy({"app_control": {"execution_rules": [
            {"id": "catalog-1", "kind": "publisher", "value": "CN=Example", "if_present": "yes"}]}})
