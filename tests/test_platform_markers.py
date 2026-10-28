"""Windows-only tests must be deselected by marker on Linux, never skipped (CI rejects skips)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
WINDOWS_SKIP = re.compile(r"skipif\(\s*os\.name\s*!=\s*[\"']nt[\"']")


@pytest.mark.parametrize("path", sorted(TESTS.glob("test_*.py")), ids=lambda path: path.name)
def test_every_windows_skip_also_carries_the_windows_only_marker(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    for number, line in enumerate(lines):
        if not WINDOWS_SKIP.search(line) or line.lstrip().startswith("#"):
            continue
        # The marker sits in the same pytestmark list or on the decorator just above.
        context = " ".join(lines[max(0, number - 2):number + 1])
        assert "windows_only" in context, f"{path.name}:{number + 1} skips on non-Windows without windows_only"
