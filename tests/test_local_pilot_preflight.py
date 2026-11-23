"""Inert guards for the physical pilot; never collect the actual machine backup."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/backup-local-pilot.ps1"
pytestmark = [pytest.mark.windows_only, pytest.mark.skipif(os.name != "nt", reason="Windows pilot guards")]


def powershell(command: str, **environment: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
        env={**os.environ, "PILOT_SCRIPT": str(SCRIPT), **environment},
        capture_output=True, text=True, timeout=30, check=False,
    )


FUNCTIONS = r"""
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($env:PILOT_SCRIPT, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Script does not parse.' }
$ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false) |
    ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }
"""


def test_plan_is_inert_and_declares_recovery_as_unverified(tmp_path):
    assert SCRIPT.is_file()
    target = tmp_path / "must-not-exist"
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(SCRIPT),
         "-Plan", "-OutputDirectory", str(target)], capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert plan["mode"] == "read_only_preflight"
    assert plan["destination"] == "Documents/OpenEMS-Lab/<run>/private"
    assert plan["rollback_status"] == "not_yet_verified"
    assert plan["requires"] == ["same_user_sid", "same_session", "administrator", "new_protected_directory"]
    assert {"configuration", "state", "authority", "cached_msi", "agent", "service", "hosts", "dns", "roots", "registry"} <= set(plan["topics"])
    assert plan["host_mutations"] == []
    assert list(tmp_path.iterdir()) == []


def test_main_rejects_another_identity_without_creating_destination(tmp_path):
    assert SCRIPT.is_file()
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(SCRIPT),
         "-OutputDirectory", str(tmp_path / "must-not-exist"),
         "-ExpectedCurrentUserSid", "S-1-0-0", "-ExpectedSessionId", "-1"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode != 0
    report = json.loads(result.stdout)
    assert report["status"] == "identity_mismatch"
    assert report["backup_complete"] is False
    assert list(tmp_path.iterdir()) == []
    assert not result.stderr.strip(), "Public failure output must be sanitized JSON only."


@pytest.mark.parametrize(("sid", "session", "admin", "error"), [
    ("S-1-5-21-200", "7", "$true", "identity_mismatch"),
    ("S-1-5-21-100", "8", "$true", "session_mismatch"),
    ("S-1-5-21-100", "7", "$false", "administrator_required"),
])
def test_identity_and_elevation_guards_are_fail_closed(sid, session, admin, error):
    assert SCRIPT.is_file()
    result = powershell(FUNCTIONS + f"""
try {{
    Assert-PilotIdentity -ExpectedSid 'S-1-5-21-100' -ExpectedSession 7 -CurrentSid '{sid}' -CurrentSession {session} -Administrator {admin}
    throw 'Guard accepted an unsafe context.'
}} catch {{ $_.Exception.Message }}
""")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == error


@pytest.mark.parametrize("kind", ["outside", "traversal", "existing", "nested", "alternate_stream", "wildcard", "relative", "trailing_dot", "reserved_name"])
def test_destination_guards_refuse_invalid_paths_without_writes(tmp_path, kind):
    assert SCRIPT.is_file()
    documents = tmp_path / "Documents"
    lab = documents / "OpenEMS-Lab"
    lab.mkdir(parents=True)
    existing = lab / "existing"
    existing.mkdir()
    target = {
        "outside": tmp_path / "outside", "traversal": lab / ".." / "outside",
        "existing": existing, "nested": lab / "run" / "nested",
        "alternate_stream": lab / "run:stream", "wildcard": lab / "run[1]", "relative": Path("relative"),
        "trailing_dot": lab / "run.", "reserved_name": lab / "CON",
    }[kind]
    before = set(tmp_path.rglob("*"))
    result = powershell(FUNCTIONS + """
try { Get-PilotDestination -OutputDirectory $env:PILOT_DESTINATION -DocumentsDirectory $env:PILOT_DOCUMENTS; throw 'Unsafe path accepted.' }
catch { $_.Exception.Message }
""", PILOT_DESTINATION=str(target), PILOT_DOCUMENTS=str(documents))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "invalid_output_directory"
    assert set(tmp_path.rglob("*")) == before


def test_new_snapshot_directory_has_only_explicit_sid_access(tmp_path):
    assert SCRIPT.is_file()
    destination = tmp_path / "private"
    result = powershell(FUNCTIONS + r"""
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
New-PilotPrivateDirectory -Path $env:PILOT_DESTINATION -UserSid $sid
$acl = (New-Object IO.DirectoryInfo($env:PILOT_DESTINATION)).GetAccessControl()
[ordered]@{
    protected = $acl.AreAccessRulesProtected
    owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    expected = $sid.Value
    rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
        ForEach-Object { @{ sid = $_.IdentityReference.Value; inherited = $_.IsInherited; rights = $_.FileSystemRights.ToString() } })
} | ConvertTo-Json -Depth 5
""", PILOT_DESTINATION=str(destination))
    assert result.returncode == 0, result.stderr
    acl = json.loads(result.stdout)
    assert acl["protected"] is True and acl["owner"] == acl["expected"]
    assert {rule["sid"] for rule in acl["rules"]} == {acl["expected"], "S-1-5-18", "S-1-5-32-544"}
    assert all(not rule["inherited"] and rule["rights"] == "FullControl" for rule in acl["rules"])


def test_stable_copy_preserves_source_and_fails_if_destination_exists(tmp_path):
    assert SCRIPT.is_file()
    source = tmp_path / "source.json"
    source.write_bytes(bytes(range(256)) * 1024)
    destination = tmp_path / "copy.json"
    result = powershell(FUNCTIONS + """
Copy-PilotFile -Source $env:PILOT_SOURCE -Destination $env:PILOT_DESTINATION | ConvertTo-Json -Depth 4
""", PILOT_SOURCE=str(source), PILOT_DESTINATION=str(destination))
    assert result.returncode == 0, result.stderr
    record = json.loads(result.stdout)
    assert record["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert record["bytes"] == source.stat().st_size
    assert destination.read_bytes() == source.read_bytes()
    result = powershell(FUNCTIONS + """
Copy-PilotFile -Source $env:PILOT_SOURCE -Destination $env:PILOT_DESTINATION
""", PILOT_SOURCE=str(source), PILOT_DESTINATION=str(destination))
    assert result.returncode != 0
    assert destination.read_bytes() == source.read_bytes()


def test_final_guard_rejects_a_source_changed_after_copy(tmp_path):
    assert SCRIPT.is_file()
    source = tmp_path / "source.json"
    source.write_bytes(b"original")
    result = powershell(FUNCTIONS + """
$record = Copy-PilotFile -Source $env:PILOT_SOURCE -Destination $env:PILOT_DESTINATION
[IO.File]::WriteAllText($env:PILOT_SOURCE, 'modified')
try { Assert-PilotFilesUnchanged @($record); throw 'Changed source accepted.' }
catch { $_.Exception.Message }
""", PILOT_SOURCE=str(source), PILOT_DESTINATION=str(tmp_path / "copy.json"))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "source_changed"
    assert (tmp_path / "copy.json").read_bytes() == b"original"


def test_script_commands_are_auditable_and_never_come_from_input():
    assert SCRIPT.is_file()
    result = powershell(FUNCTIONS + r"""
$functions = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false) | ForEach-Object { $_.Name })
$commands = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() })
@{ functions = $functions; commands = $commands } | ConvertTo-Json -Depth 4
""")
    assert result.returncode == 0, result.stderr
    ast = json.loads(result.stdout)
    allowed = {
        "ConvertTo-Json", "ConvertFrom-Json", "Get-Service", "Get-DnsClientServerAddress",
        "Get-DnsClientNrptPolicy", "Get-NetFirewallRule", "Import-Module", "Join-Path",
        "New-Object", "Select-Object", "Sort-Object", "ForEach-Object", "Where-Object", "Set-StrictMode",
    } | set(ast["functions"])
    assert set(ast["commands"]) <= allowed


def test_script_has_no_machine_mutations_and_keeps_sensitive_data_private():
    source = SCRIPT.read_text(encoding="utf-8")
    for forbidden in (
        "Set-Acl", "Win32_Product", "msiexec", "Start-Process", "Stop-Service", "Start-Service",
        "Restart-Service", "Set-Dns", "Add-Dns", "Remove-Dns", "Set-ItemProperty", "New-ItemProperty",
        "Remove-Item", ".SetValue(", ".CreateSubKey(", ".AddStore(", "Invoke-Expression",
    ):
        assert forbidden.casefold() not in source.casefold(), forbidden
    assert "SetAccessRuleProtection($true, $false)" in source
    assert "FileMode]::CreateNew" in source
    assert "LocalPackage" in source and "Uninstall" in source and "UserData" in source
    assert "Assert-PilotFilesUnchanged" in source
    assert "CurrentUser" in source and "LocalMachine" in source
    for journal in ("application-control.json", "usb-control.json", "uninstall.json", "browser-policies.json"):
        assert journal in source
    assert "not_yet_verified" in source
