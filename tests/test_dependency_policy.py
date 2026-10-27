"""Supply-chain policy for the server image (2026-10-27 security review).

The production image installs only runtime packages from a fully hashed lock; test tools live in
requirements-dev.txt. Minimum versions close the advisories found by pip-audit/osv/Trivy.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN = re.compile(r"^([A-Za-z0-9_.\[\]-]+)==([0-9][^\s;\\]*)")
DEV_ONLY = {"pytest", "pytest-cov", "httpx", "ruff", "playwright", "pywin32", "mypy", "pip-audit", "bandit"}
# Fixed versions for the advisories reported on 2026-10-27 (starlette via fastapi, python-multipart).
MINIMUMS = {"fastapi": (0, 162, 0), "python-multipart": (0, 0, 31), "starlette": (1, 3, 1), "anyio": (4, 15, 0),
            "urllib3": (2, 8, 0), "certifi": (2026, 10, 23)}


def pins(path: Path) -> dict[str, str]:
    found = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = PIN.match(line.strip())
        if match:
            found[match.group(1).split("[")[0].lower()] = match.group(2)
    return found


def version(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", text)[:3])


def test_runtime_requirements_exclude_test_tools():
    runtime = pins(ROOT / "requirements.txt")
    assert not DEV_ONLY & set(runtime), "test tools must not be installed in the production image"
    dev = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
    assert "-r requirements.txt" in dev
    assert {"pytest", "ruff"} <= set(pins(ROOT / "requirements-dev.txt"))


def test_lock_pins_every_package_with_hashes():
    lines = (ROOT / "requirements.lock").read_text(encoding="utf-8").replace("\\\n", " ").splitlines()
    entries = [line for line in lines if PIN.match(line.strip())]
    assert entries, "lock is empty"
    assert all("--hash=sha256:" in line for line in entries), "every locked package needs a hash"
    locked = pins(ROOT / "requirements.lock")
    assert set(pins(ROOT / "requirements.txt")) <= set(locked)
    assert not DEV_ONLY & set(locked)


def test_locked_versions_close_reviewed_advisories():
    locked = pins(ROOT / "requirements.lock")
    assert {"fastapi", "starlette", "python-multipart"} <= set(locked)
    for name, minimum in MINIMUMS.items():
        # Transitive packages may leave the runtime entirely; when present they must be fixed.
        if name in locked:
            assert version(locked[name]) >= minimum, f"{name} {locked[name]} is below {minimum}"


def test_image_installs_the_hashed_lock_only():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "--require-hashes" in dockerfile and "requirements.lock" in dockerfile
    assert "-r requirements.txt" not in dockerfile


def test_base_images_are_pinned_by_digest():
    froms = re.findall(r"^FROM\s+(\S+)", (ROOT / "Dockerfile").read_text(encoding="utf-8"), flags=re.MULTILINE)
    assert froms and all(re.search(r"@sha256:[0-9a-f]{64}$", image) for image in froms if image not in {"builder", "panel"})


def test_final_stage_is_minimal_and_observable():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    final = re.split(r"^FROM .+$", dockerfile, flags=re.MULTILINE)[-1]
    assert "HEALTHCHECK" in final
    # PATH prefers the venv, whose pip is already gone: the system interpreter must be named.
    assert re.search(r"/usr/local/bin/python -m pip uninstall -y pip", final), "the runtime layer must not keep an installer"
    assert re.search(r"^USER 10001:10001$", final, flags=re.MULTILINE)
