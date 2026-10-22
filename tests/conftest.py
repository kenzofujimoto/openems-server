"""Shared fixtures for the native agent contract and service suites."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EXE = ".exe" if os.name == "nt" else ""


def _binary() -> Path | None:
    configured = os.environ.get("OPENEMS_NATIVE_AGENT")
    candidates = [Path(configured)] if configured else [
        ROOT / "agent-rs" / "target" / profile / f"openems-agent{EXE}" for profile in ("release", "debug")
    ]
    return next((path for path in candidates if path.is_file()), None)


@pytest.fixture(scope="module")
def native() -> Path:
    binary = _binary()
    if binary is None:
        if os.environ.get("OPENEMS_REQUIRE_NATIVE_AGENT") == "1":
            pytest.fail("native agent binary is required but was not built")
        pytest.skip("native agent is not built; run cargo build in agent-rs")
    return binary
