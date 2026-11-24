"""Inert guards for the physical pilot; never collect the actual machine backup."""

from __future__ import annotations

import hashlib
import base64
import json
import os
from pathlib import Path
import subprocess
from datetime import UTC, datetime, timedelta

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/backup-local-pilot.ps1"
pytestmark = [pytest.mark.windows_only, pytest.mark.skipif(os.name != "nt", reason="Windows pilot guards")]


@pytest.fixture(autouse=True)
def isolate_powershell_module_cache(tmp_path_factory, monkeypatch):
    cache = tmp_path_factory.mktemp("powershell-module-cache")
    monkeypatch.setenv("PSModuleAnalysisCachePath", str(cache / "ModuleAnalysisCache"))


def powershell(command: str, **environment: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
        env={**os.environ, "PILOT_SCRIPT": str(SCRIPT), **environment},
        capture_output=True, text=True, timeout=30, check=False,
    )


FUNCTIONS = r"""
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1')
$PSModuleAutoLoadingPreference = 'None'
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
    # Decode only public DER certificates; a PFX constructor could import a private key.
    assert "GetCertContentType" in source and "X509ContentType]::Cert" in source


def caller_context(documents: Path, **changes):
    value = {
        "schema_version": 1,
        "captured_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z",
        "user_sid": "S-1-5-21-100", "session_id": 7, "documents": str(documents),
        "roots": {"CurrentUser": [], "LocalMachine": []},
    }
    value.update(changes)
    return value


def test_context_capture_plan_is_inert(tmp_path):
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(SCRIPT),
         "-Plan", "-CaptureCallerContext", "-OutputDirectory", str(tmp_path / "absent")],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert plan["mode"] == "caller_context_capture"
    assert plan["requires"] == ["same_user_sid", "same_session", "unelevated", "new_protected_directory"]
    assert plan["context_max_age_seconds"] == 900
    assert plan["topics"] == ["caller_identity", "documents", "roots", "captured_at"]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("argument", ["-CallerContextPath", "-CallerContextSha256"])
def test_partial_context_options_fail_before_host_reads_or_writes(tmp_path, argument):
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(SCRIPT),
         "-OutputDirectory", str(tmp_path / "absent"), argument, "invalid"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode != 0
    report = json.loads(result.stdout)
    assert report["status"] == "caller_context_pair_required"
    assert report["snapshot_created"] is False and report["file_count"] == 0
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(("session", "administrator", "error"), [
    (8, "$true", "session_mismatch"), (7, "$false", "administrator_required"),
])
def test_delegated_guard_still_requires_same_interactive_session_and_admin(session, administrator, error):
    result = powershell(FUNCTIONS + f"""
try {{ Assert-PilotDelegatedIdentity -ExpectedSession 7 -CurrentSession {session} -Administrator {administrator}; throw 'Unsafe context accepted.' }}
catch {{ $_.Exception.Message }}
""")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == error


@pytest.mark.parametrize("case", ["valid", "wrong_hash", "tampered", "stale", "future", "wrong_sid", "wrong_session", "wrong_schema", "extra_field", "bad_roots"])
def test_pinned_context_validation_uses_inert_files_only(tmp_path, case):
    value = caller_context(tmp_path / "Documents")
    if case in {"stale", "future"}:
        offset = timedelta(hours=-1 if case == "stale" else 1)
        value["captured_at"] = (datetime.now(UTC) + offset).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
    elif case == "wrong_sid":
        value["user_sid"] = "S-1-5-21-200"
    elif case == "wrong_session":
        value["session_id"] = 8
    elif case == "wrong_schema":
        value["schema_version"] = 2
    elif case == "extra_field":
        value["untrusted_extra"] = "must not be accepted"
    elif case == "bad_roots":
        value["roots"] = {"CurrentUser": "not an array", "LocalMachine": []}
    path = tmp_path / "caller-context.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if case == "tampered":
        path.write_text(json.dumps({**value, "documents": "C:\\OtherUser\\Documents"}), encoding="utf-8")
    elif case == "wrong_hash":
        digest = "0" * 64
    before = path.read_bytes()
    result = powershell(FUNCTIONS + """
try {
    $context = Read-PilotCallerContext -LiteralPath $env:PILOT_CONTEXT -Sha256 $env:PILOT_HASH -ExpectedSid 'S-1-5-21-100' -ExpectedSession 7
    @{ accepted = $true; sid = $context.user_sid } | ConvertTo-Json -Depth 3
} catch { $_.Exception.Message }
""", PILOT_CONTEXT=str(path), PILOT_HASH=digest)
    assert result.returncode == 0, result.stderr
    if case == "valid":
        assert json.loads(result.stdout) == {"accepted": True, "sid": value["user_sid"]}
    else:
        assert result.stdout.strip() in {
            "caller_context_hash_mismatch", "caller_context_stale", "identity_mismatch",
            "session_mismatch", "caller_context_invalid",
        }
    assert path.read_bytes() == before


@pytest.mark.parametrize("case", ["default", "onedrive", "onedrive_variable", "outside", "prefix_collision", "unknown_variable", "unc", "relative", "context_mismatch"])
def test_original_documents_resolution_never_uses_admin_environment(tmp_path, case):
    profile = tmp_path / "Original"
    profile.mkdir()
    documents = profile / "Documents"
    personal = r"%USERPROFILE%\Documents"
    environment = {}
    if case in {"onedrive", "onedrive_variable"}:
        documents = profile / "OneDrive - Inert" / "Documents"
        personal = r"%USERPROFILE%\OneDrive - Inert\Documents"
        if case == "onedrive_variable":
            personal = r"%OneDriveCommercial%\Documents"
            environment = {"OneDriveCommercial": str(profile / "OneDrive - Inert")}
    elif case == "outside":
        documents = tmp_path / "Outside" / "Documents"
        personal = str(documents)
    elif case == "prefix_collision":
        documents = tmp_path / "OriginalSibling" / "Documents"
        personal = str(documents)
    elif case == "unknown_variable":
        personal = r"%USERPROFILE%\%ADMIN_ONLY_VARIABLE%\Documents"
    elif case == "unc":
        personal = r"\\untrusted\share\Documents"
    elif case == "relative":
        personal = r"relative\Documents"
    documents.mkdir(parents=True)
    context_documents = documents if case != "context_mismatch" else profile / "OtherDocuments"
    fixture = tmp_path / "profile.json"
    fixture.write_text(json.dumps({"profile": str(profile), "personal": personal, "documents": str(context_documents), "environment": environment}), encoding="utf-8")
    result = powershell(FUNCTIONS + """
$fixture = [IO.File]::ReadAllText($env:PILOT_PROFILE) | ConvertFrom-Json
$originalEnvironment = @{}
foreach ($property in $fixture.environment.PSObject.Properties) { $originalEnvironment[$property.Name] = [string]$property.Value }
try { Resolve-PilotOriginalDocuments -ProfileImagePath $fixture.profile -PersonalPath $fixture.personal -ContextDocuments $fixture.documents -OriginalEnvironment $originalEnvironment }
catch { $_.Exception.Message }
""", PILOT_PROFILE=str(fixture), USERPROFILE=str(tmp_path / "WrongAdmin"), OneDriveCommercial=str(tmp_path / "WrongAdminOneDrive"))
    assert result.returncode == 0, result.stderr
    if case in {"default", "onedrive", "onedrive_variable"}:
        assert result.stdout.strip() == str(documents)
    else:
        assert result.stdout.strip() == "original_documents_invalid"


def test_delegated_acl_has_original_grant_and_actual_owner_without_extra_account_grant():
    result = powershell(FUNCTIONS + r"""
$actual = [Security.Principal.WindowsIdentity]::GetCurrent().User
$original = New-Object Security.Principal.SecurityIdentifier('S-1-5-21-100')
$security = New-PilotDirectorySecurity -UserSid $original -OwnerSid $actual
@{
    owner = $security.GetOwner([Security.Principal.SecurityIdentifier]).Value
    actual = $actual.Value
    grants = @($security.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value })
} | ConvertTo-Json -Depth 4
""")
    assert result.returncode == 0, result.stderr
    security = json.loads(result.stdout)
    assert security["owner"] == security["actual"]
    assert set(security["grants"]) == {"S-1-5-21-100", "S-1-5-18", "S-1-5-32-544"}


@pytest.mark.parametrize("changed", [False, True])
def test_delegated_roots_take_current_user_only_from_pinned_original_context(tmp_path, changed):
    fixture = tmp_path / "context.json"
    fixture.write_text(json.dumps(caller_context(tmp_path, roots={
        "CurrentUser": [{"thumbprint": "original-user", "certificate": "original-public-certificate"}], "LocalMachine": [],
    })), encoding="utf-8")
    result = powershell(FUNCTIONS + r"""
function Get-PilotRoots([string[]]$Locations) {
    if ($Locations -contains 'CurrentUser') { throw 'Administrator CurrentUser store requested.' }
    $machine = @()
    if ($env:PILOT_CHANGED -eq 'yes') { $machine = @(@{ thumbprint = 'new-machine-root'; certificate = 'new-public-certificate' }) }
    @{ LocalMachine = $machine; CurrentUser = @('administrator-root-must-never-appear') }
}
$context = [IO.File]::ReadAllText($env:PILOT_CONTEXT) | ConvertFrom-Json
try { Get-PilotEffectiveRoots -CallerContext $context | ConvertTo-Json -Depth 5 }
catch { $_.Exception.Message }
""", PILOT_CONTEXT=str(fixture), PILOT_CHANGED="yes" if changed else "no")
    assert result.returncode == 0, result.stderr
    if changed:
        assert result.stdout.strip() == "machine_roots_changed"
    else:
        roots = json.loads(result.stdout)
        assert roots["CurrentUser"] == [{"thumbprint": "original-user", "certificate": "original-public-certificate"}]
        assert roots["LocalMachine"] == []
        assert "administrator-root" not in result.stdout


def test_context_file_cannot_be_rewritten_during_hashing_or_json_parsing(tmp_path):
    context = tmp_path / "context.json"
    context.write_text(json.dumps(caller_context(tmp_path)), encoding="utf-8")
    digest = hashlib.sha256(context.read_bytes()).hexdigest()
    result = powershell(FUNCTIONS + r"""
function Test-FixtureWriteLock {
    try {
        $writer = [IO.File]::Open($env:PILOT_CONTEXT, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
        $writer.Dispose()
        $false
    } catch { $true }
}
function Get-PilotHash([IO.Stream]$Stream) {
    $script:hashLocked = Test-FixtureWriteLock
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($hasher.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant() }
    finally { $hasher.Dispose() }
}
function ConvertFrom-Json {
    param([Parameter(ValueFromPipeline = $true)]$InputObject)
    process {
        $script:jsonLocked = Test-FixtureWriteLock
        Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $InputObject
    }
}
$value = Read-PilotCallerContext -LiteralPath $env:PILOT_CONTEXT -Sha256 $env:PILOT_HASH -ExpectedSid 'S-1-5-21-100' -ExpectedSession 7
@{ hash_locked = $script:hashLocked; json_locked = $script:jsonLocked } | ConvertTo-Json
""", PILOT_CONTEXT=str(context), PILOT_HASH=digest)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"hash_locked": True, "json_locked": True}
    assert hashlib.sha256(context.read_bytes()).hexdigest() == digest


@pytest.mark.parametrize("administrator", [True, False])
def test_caller_capture_guard_requires_original_unelevated_identity(administrator):
    admin = "$true" if administrator else "$false"
    result = powershell(FUNCTIONS + f"""
try {{
    Assert-PilotCaptureIdentity -ExpectedSid 'S-1-5-21-100' -ExpectedSession 7 -CurrentSid 'S-1-5-21-100' -CurrentSession 7 -Administrator {admin}
    'accepted'
}} catch {{ $_.Exception.Message }}
""")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ("caller_context_requires_unelevated" if administrator else "accepted")


@pytest.fixture(scope="module")
def public_der_certificate():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    # The synthetic signing key stays in memory; only public DER enters the fixture.
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "inert-caller-context")])
    now = datetime.now(UTC)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                   .sign(key, hashes.SHA256()))
    der = certificate.public_bytes(serialization.Encoding.DER)
    return {
        # Match the Windows store's legacy identifier; this does not establish trust.
        "thumbprint": hashlib.sha1(der, usedforsecurity=False).hexdigest().upper(),
        "certificate": base64.b64encode(der).decode(),
    }


@pytest.mark.parametrize("case", ["public_der", "wrong_thumbprint", "duplicate"])
def test_pinned_context_validates_nonempty_public_certificate_rows(tmp_path, public_der_certificate, case):
    row = dict(public_der_certificate)
    if case == "wrong_thumbprint":
        row["thumbprint"] = "A" * 40
    rows = [row, row] if case == "duplicate" else [row]
    path = tmp_path / "context.json"
    path.write_text(json.dumps(caller_context(tmp_path, roots={"CurrentUser": rows, "LocalMachine": rows})), encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    result = powershell(FUNCTIONS + """
try {
    $value = Read-PilotCallerContext -LiteralPath $env:PILOT_CONTEXT -Sha256 $env:PILOT_HASH -ExpectedSid 'S-1-5-21-100' -ExpectedSession 7
    'accepted'
} catch { $_.Exception.Message }
""", PILOT_CONTEXT=str(path), PILOT_HASH=digest)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ("accepted" if case == "public_der" else "caller_context_invalid")
