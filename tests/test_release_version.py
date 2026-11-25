"""Release metadata and inert MSI planning share the server's canonical version."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tomllib

import pytest

from app import __version__
from app.api import create_app

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "tools/build-msi-fixtures.ps1"


def plan(builder: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    powershell = shutil.which("powershell.exe")
    assert powershell, "Windows PowerShell is required for inert MSI build planning."
    return subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(builder), "-Plan", *arguments],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, check=False,
    )


def copied_builder(tmp_path: Path, metadata: str) -> Path:
    tools = tmp_path / "tools"
    tools.mkdir()
    application = tmp_path / "app"
    application.mkdir()
    target = tools / BUILDER.name
    shutil.copyfile(BUILDER, target)
    (application / "__init__.py").write_text(metadata, encoding="utf-8")
    return target


def test_canonical_version_declares_windows_v1_release():
    assert __version__ == "1.0.0"


def test_fastapi_reports_the_canonical_release_version():
    assert create_app().version == __version__


def test_cargo_manifest_and_self_package_lock_match_the_canonical_version():
    manifest = tomllib.loads((ROOT / "agent-rs/Cargo.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((ROOT / "agent-rs/Cargo.lock").read_text(encoding="utf-8"))
    (package,) = [item for item in lock["package"] if item["name"] == "openems-agent"]
    assert manifest["package"]["version"] == __version__
    assert package["version"] == __version__


def test_panel_manifest_and_both_lock_versions_match_the_canonical_version():
    manifest = json.loads((ROOT / "web/package.json").read_text(encoding="utf-8"))
    lock = json.loads((ROOT / "web/package-lock.json").read_text(encoding="utf-8"))
    assert manifest["version"] == __version__
    assert lock["version"] == __version__
    assert lock["packages"][""]["version"] == __version__


def test_ci_uses_the_production_builder_for_the_promotable_msi():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    step = re.search(r"(?ms)^      - name: Build MSI\n.*?(?=^      - name:|\Z)", workflow)
    assert step is not None
    command = step.group(0)
    assert "tools/build-msi-fixtures.ps1" in command
    assert "-Production" in command
    assert "-OutputDirectory" in command
    assert "Version=" not in command and "wix build" not in command
    assert "-Next" not in command and "FaultInjection" not in command


@pytest.mark.windows_only
@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell build-plan contracts")
@pytest.mark.parametrize(("arguments", "version", "filename"), [
    (("-Production",), "1.0.0", "openems-agent.msi"),
    (("-Production", "-Next"), "1.0.1", "openems-agent-next.msi"),
])
def test_production_and_internal_upgrade_plans_omit_fault_injection(arguments, version, filename):
    result = plan(BUILDER, *arguments)
    assert result.returncode == 0, result.stderr
    package = json.loads(result.stdout)
    assert package == {"fixtures": [filename], "defines": [], "versions": [version]}


@pytest.mark.windows_only
@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell build-plan contracts")
@pytest.mark.parametrize(("arguments", "expected"), [
    (("-Production",), "2.7.9"),
    (("-Production", "-Next"), "2.7.10"),
])
def test_builder_reads_canonical_metadata_and_derives_the_next_patch(tmp_path, arguments, expected):
    builder = copied_builder(tmp_path, '__version__ = "2.7.9"\n')
    result = plan(builder, *arguments)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["versions"] == [expected]
    assert not (tmp_path / "agent-rs").exists(), "Planning must not create or build the agent."


@pytest.mark.windows_only
@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell build-plan contracts")
@pytest.mark.parametrize("metadata", [
    "",
    '__version__ = "1.0.0rc1"\n',
    '__version__ = "1.0.0.1"\n',
    '__version__ = "01.0.0"\n',
    '__version__ = "1.0.0"\n__version__ = "2.0.0"\n',
])
def test_builder_refuses_missing_ambiguous_or_non_release_metadata(tmp_path, metadata):
    builder = copied_builder(tmp_path, metadata)
    result = plan(builder, "-Production")
    assert result.returncode != 0


@pytest.mark.windows_only
@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell build-plan contracts")
def test_builder_never_executes_python_version_metadata(tmp_path):
    marker = tmp_path / "metadata-executed"
    builder = copied_builder(tmp_path, f"__version__ = open({str(marker)!r}, 'w').write('executed')\n")
    result = plan(builder, "-Production")
    assert result.returncode != 0
    assert not marker.exists()
