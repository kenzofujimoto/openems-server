"""The shared vectors must stay in sync with the Python policy implementation."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _generator():
    spec = importlib.util.spec_from_file_location("gen_policy_vectors", ROOT / "tools" / "gen_policy_vectors.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_committed_vectors_match_policy_module():
    committed = (ROOT / "contract" / "policy-vectors.json").read_text(encoding="utf-8")
    assert committed == _generator().render(), "run: python tools/gen_policy_vectors.py"


def test_vectors_cover_valid_and_invalid_cases():
    vectors = _generator().build()
    for section in ("domains", "domain_rules", "processes", "validate"):
        outcomes = vectors[section]
        assert any("error" in item for item in outcomes)
        assert any("normalized" in item for item in outcomes)
    assert len({item["digest"] for item in vectors["policies"]}) == len(vectors["policies"])


def test_vectors_cover_rule_matching_both_ways():
    vectors = _generator().build()
    assert {item["result"] for item in vectors["matches"]} == {True, False}
    assert any(item["allowed"] for item in vectors["hosts_names"])


def test_vectors_cover_web_actions_and_explicit_nonlogging_permissions():
    decisions = _generator().build()["web_actions"]
    assert {case["decision"]["action"] for case in decisions} == {"allow", "block", "monitor"}
    assert any(case["web_filter"].get("allowed") and not case["decision"]["log"] for case in decisions)
    assert any(case["web_filter"].get("monitor_all") and case["decision"]["reason"] == "observation"
               for case in decisions)
    assert any(case["web_filter"].get("scheduled") for case in decisions)
