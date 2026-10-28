"""Safety contracts for the disposable Windows trust acceptance harness."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy/test-trust-sandbox.ps1"


@pytest.mark.windows_only
@pytest.mark.skipif(os.name != "nt", reason="Windows directory security descriptors")
def test_acceptance_plan_restricts_directory_writes_and_is_read_only(tmp_path):
    command = (
        "$plan = & $env:OPENEMS_HARNESS -Plan -OutputDirectory $env:PROBE_OUTPUT | ConvertFrom-Json; "
        "$acl = New-Object System.Security.AccessControl.DirectorySecurity; "
        "$acl.SetSecurityDescriptorSddlForm($plan.directory_sddl); "
        "$sid = [System.Security.Principal.SecurityIdentifier]; "
        "@{ owner=$acl.GetOwner($sid).Value; protected=$acl.AreAccessRulesProtected; "
        "rules=@($acl.GetAccessRules($true,$true,$sid) | ForEach-Object { "
        "@{sid=$_.IdentityReference.Value; rights=$_.FileSystemRights.ToString(); type=$_.AccessControlType.ToString()} }); "
        "work=$plan.work_directory } | ConvertTo-Json -Depth 5"
    )
    environment = {**os.environ, "OPENEMS_HARNESS": str(SCRIPT), "PROBE_OUTPUT": str(tmp_path)}
    plans = []
    for _ in range(2):
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", command],
            env=environment, capture_output=True, text=True, check=False, timeout=30,
        )
        assert result.returncode == 0, result.stderr
        plan = json.loads(result.stdout)
        assert plan["owner"] == "S-1-5-32-544"
        assert plan["protected"] is True
        assert {rule["sid"] for rule in plan["rules"]} == {"S-1-5-18", "S-1-5-32-544"}
        assert all(rule["rights"] == "FullControl" and rule["type"] == "Allow" for rule in plan["rules"])
        plans.append(plan)
    assert plans[0]["work"] != plans[1]["work"]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.windows_only
@pytest.mark.skipif(os.name != "nt", reason="PowerShell environment probe")
@pytest.mark.parametrize("profile,service,expected", [(True, True, "True"), (True, False, "False"), (False, True, "False"), (False, False, "False")])
def test_sandbox_detection_uses_profile_and_running_execution_service(profile, service, expected):
    command = (
        "function Test-Path { param($LiteralPath) return ($env:PROBE_PROFILE -eq '1') }; "
        "function Get-Service { param($Name, $ErrorAction) "
        "if ($env:PROBE_SERVICE -eq '1') { [pscustomobject]@{Status='Running'} } }; "
        "& $env:OPENEMS_HARNESS -ProbeEnvironment"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", command],
        env={**os.environ, "OPENEMS_HARNESS": str(SCRIPT), "PROBE_PROFILE": str(int(profile)), "PROBE_SERVICE": str(int(service))},
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected


def test_sandbox_acceptance_harness_exists():
    assert SCRIPT.is_file()


@pytest.mark.windows_only
@pytest.mark.skipif(os.name != "nt", reason="PowerShell Windows host guard")
def test_harness_refuses_the_development_host_before_writing(tmp_path):
    assert SCRIPT.is_file()
    shell = shutil.which("powershell.exe")
    assert shell
    result = subprocess.run(
        [shell, "-NoProfile", "-File", str(SCRIPT), "-OutputDirectory", str(tmp_path)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert result.returncode != 0
    assert "requires Windows Sandbox" in result.stderr
    assert list(tmp_path.iterdir()) == []


@pytest.mark.windows_only
@pytest.mark.skipif(os.name != "nt", reason="PowerShell parser")
def test_harness_has_valid_powershell_syntax():
    assert SCRIPT.is_file()
    command = (
        "$tokens=$null; $errors=$null; "
        "[System.Management.Automation.Language.Parser]::ParseFile("
        "$env:OPENEMS_HARNESS, [ref]$tokens, [ref]$errors) | Out-Null; "
        "if ($errors.Count) { $errors | Out-String | Write-Error; exit 1 }"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", command],
        env={**os.environ, "OPENEMS_HARNESS": str(SCRIPT)},
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert result.returncode == 0, result.stderr
