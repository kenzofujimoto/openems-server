"""Inspect MSI tables and exact embedded bytes without running installation actions."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

import pytest

from app import __version__

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/inspect-msi.ps1"
pytestmark = [pytest.mark.windows_only, pytest.mark.skipif(os.name != "nt", reason="Windows Installer COM")]


def inspect(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(SCRIPT), "-LiteralPath", str(path)],
        capture_output=True, text=True, timeout=90, check=False,
    )


def test_inspector_parses_and_exposes_only_the_literal_input_parameter():
    assert SCRIPT.is_file()
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($env:INSPECTOR, [ref]$tokens, [ref]$errors)
if ($errors.Count) { $errors | Out-String | Write-Error; exit 1 }
ConvertTo-Json -InputObject @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) -Compress
"""
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
        env={**os.environ, "INSPECTOR": str(SCRIPT)}, capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == ["LiteralPath"]


def test_inspector_has_no_installation_or_persistent_write_operations():
    source = SCRIPT.read_text(encoding="utf-8")
    assert re.search(r"\.OpenDatabase\([^\n]+,\s*0\)", source), "MSI database must open read-only."
    forbidden = (
        "msiexec", "Win32_Product", "InstallProduct", "ConfigureProduct", "ReinstallProduct",
        "Start-Process", "Invoke-Expression", "ScriptBlock]::Create", "Set-Content", "Out-File",
        "WriteAll", "SetStream", ".Commit(", ".Modify(", "Start-Service", "Stop-Service",
        "New-Service", "Remove-Item", "Set-Item", "Invoke-Item",
    )
    for operation in forbidden:
        assert operation.casefold() not in source.casefold(), operation


@pytest.mark.parametrize("kind", ["invalid", "missing", "directory"])
def test_invalid_input_fails_without_output_files_or_input_modification(tmp_path, kind):
    assert SCRIPT.is_file()
    # Brackets and shell metacharacters must remain a literal file name.
    path = tmp_path / "invalid[1];$(Set-Content injected.txt bad).msi"
    if kind == "invalid":
        path.write_bytes(b"not an installer database\x00\xff")
    elif kind == "directory":
        path.mkdir()
    before = {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    result = inspect(path)
    assert result.returncode != 0
    assert result.stderr.strip()
    assert not result.stdout.strip(), "Failed inspection cannot emit promotion metadata."
    after = {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert after == before
    assert not (ROOT / "injected.txt").exists()
    assert set(tmp_path.iterdir()) == ({path} if kind != "missing" else set())


def test_inert_database_preserves_every_binary_byte_across_stream_chunks(tmp_path):
    assert SCRIPT.is_file()
    payload = tmp_path / "bytes.bin"
    # More than one 64 KiB chunk, all byte values, embedded NULs and an odd final byte.
    payload.write_bytes(bytes(range(256)) * 257 + b"x")
    msi = tmp_path / "inert[1].msi"
    command = r"""
$ErrorActionPreference = 'Stop'
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase($env:FIXTURE_MSI, 3)
foreach ($sql in @(
    'CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) PRIMARY KEY `Property`)',
    'CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL PRIMARY KEY `Action`)',
    'CREATE TABLE `Binary` (`Name` CHAR(72) NOT NULL, `Data` OBJECT NOT NULL PRIMARY KEY `Name`)',
    "INSERT INTO ``Property`` (``Property``, ``Value``) VALUES ('ProductVersion', '2.7.9')",
    "INSERT INTO ``Property`` (``Property``, ``Value``) VALUES ('UpgradeCode', '{0C684B18-7540-4865-9516-567A9E81AA61}')",
    "INSERT INTO ``CustomAction`` (``Action``, ``Type``) VALUES ('InspectOnly', 0)"
)) {
    $view = $database.OpenView($sql)
    $view.Execute()
    $view.Close()
}
$record = $installer.CreateRecord(2)
$record.GetType().InvokeMember('StringData', 'SetProperty', $null, $record, @(1, 'AgentActions'))
$record.SetStream(2, $env:FIXTURE_PAYLOAD)
$view = $database.OpenView('INSERT INTO `Binary` (`Name`, `Data`) VALUES (?, ?)')
$view.Execute($record)
$view.Close()
$database.Commit()
"""
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
        env={**os.environ, "FIXTURE_MSI": str(msi), "FIXTURE_PAYLOAD": str(payload)},
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr
    before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in tmp_path.iterdir()}
    result = inspect(msi)
    assert result.returncode == 0, result.stderr
    metadata = json.loads(result.stdout)
    assert metadata["product_version"] == "2.7.9"
    assert metadata["custom_actions"] == ["InspectOnly"]
    assert metadata["properties"] == ["ProductVersion", "UpgradeCode"]
    assert metadata["agent_actions_sha256"] == hashlib.sha256(payload.read_bytes()).hexdigest()
    assert metadata["signature_status"] in {"NotSigned", "UnknownError"}
    assert {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in tmp_path.iterdir()} == before


@pytest.mark.skipif(not os.environ.get("OPENEMS_MSI"), reason="OPENEMS_MSI is not configured")
def test_real_production_msi_metadata_and_binary_payload_are_read_only():
    msi = Path(os.environ["OPENEMS_MSI"]).resolve()
    agent = ROOT / "agent-rs/target/release/openems-agent.exe"
    assert msi.is_file() and agent.is_file(), "CI must provide the production MSI and release executable."
    before = hashlib.sha256(msi.read_bytes()).hexdigest()
    result = inspect(msi)
    assert result.returncode == 0, result.stderr
    metadata = json.loads(result.stdout)
    assert set(metadata) == {
        "product_version", "upgrade_code", "custom_actions", "properties",
        "agent_actions_sha256", "signature_status",
    }
    assert metadata["product_version"] == __version__
    assert metadata["upgrade_code"].strip("{}").upper() == "0C684B18-7540-4865-9516-567A9E81AA61"
    assert metadata["signature_status"] == "NotSigned"
    assert {"PrepareAgentSetup", "PrepareAgentRemoval"} <= set(metadata["custom_actions"])
    assert not {"InjectSetupFailure", "InjectRemovalFailure"} & set(metadata["custom_actions"])
    assert not {"FAIL_SETUP", "FAIL_REMOVAL"} & set(metadata["properties"])
    assert {"ProductVersion", "UpgradeCode"} <= set(metadata["properties"])
    for field in ("custom_actions", "properties"):
        assert isinstance(metadata[field], list)
        assert len(metadata[field]) == len(set(metadata[field]))
    assert metadata["agent_actions_sha256"] == hashlib.sha256(agent.read_bytes()).hexdigest()
    assert hashlib.sha256(msi.read_bytes()).hexdigest() == before
