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
    for section in ("domains", "processes", "validate"):
        outcomes = vectors[section]
        assert any("error" in item for item in outcomes)
        assert any("normalized" in item for item in outcomes)
    assert len({item["digest"] for item in vectors["policies"]}) == len(vectors["policies"])
