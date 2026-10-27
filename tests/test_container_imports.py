"""The final Docker stage must include every local module imported by the API."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_production_runtime_sources_can_import_the_api_without_the_checkout(tmp_path):
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    final_stage = re.split(r"^FROM .+$", dockerfile, flags=re.MULTILINE)[-1]
    for source, destination in re.findall(r"^COPY (?!-)(\S+) (\S+)\s*$", final_stage, flags=re.MULTILINE):
        origin, target = ROOT / source, tmp_path / destination
        if origin.is_dir():
            shutil.copytree(origin, target, ignore=shutil.ignore_patterns("__pycache__"), dirs_exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            if destination.endswith("/") or destination == ".":
                target.mkdir(parents=True, exist_ok=True)
                target /= origin.name
            shutil.copyfile(origin, target)
    result = subprocess.run(
        [sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); import app.api", str(tmp_path)],
        cwd=tmp_path, capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr


def test_final_stage_ships_every_migration_for_the_runner():
    # apply_migrations defaults to <repo>/migrations; the image must ship it (found in the
    # 2026-10-27 guest acceptance, where the runner failed inside the production image).
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    final_stage = re.split(r"^FROM .+$", dockerfile, flags=re.MULTILINE)[-1]
    assert re.search(r"^COPY migrations \./migrations\s*$", final_stage, flags=re.MULTILINE)


def test_migration_runner_entry_point_requires_a_database_url():
    environment = {key: value for key, value in os.environ.items() if key != "OPENEMS_DATABASE_URL"}
    result = subprocess.run([sys.executable, "-m", "app.migrations"], cwd=ROOT, capture_output=True, text=True,
                            timeout=30, check=False, env=environment)
    assert result.returncode != 0
    assert "OPENEMS_DATABASE_URL" in result.stderr
