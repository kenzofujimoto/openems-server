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
        "New-Object", "Select-Object", "Sort-Object", "ForEach-Object", "Where-Object", "Set-StrictMode", "Add-Type",
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


@pytest.mark.parametrize("case", ["outside", "relative", "alternate_stream", "parent_escape"])
def test_protected_authority_scope_is_checked_before_privilege_or_read(case):
    result = powershell(FUNCTIONS + r"""
$canonical = [IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'), 'openems\https\authority.json')
$path = switch ($env:PILOT_CASE) {
    outside { [IO.Path]::Combine([Environment]::GetFolderPath('Windows'), 'outside.json') }
    relative { 'authority.json' }
    alternate_stream { $canonical + ':secret' }
    parent_escape { [IO.Path]::Combine([IO.Path]::GetDirectoryName($canonical), '..\other.json') }
}
function Enable-PilotBackupPrivilege { throw 'privilege must not be requested' }
function Open-PilotAuthorityHandle { throw 'source must not be opened' }
try { Open-PilotAuthorityRead $path; throw 'outside source accepted' }
catch { $_.Exception.Message }
""", PILOT_CASE=case)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "authority_path_untrusted"


@pytest.mark.parametrize("case", ["success", "read_failure", "privilege_unavailable", "restore_failure", "missing"])
def test_authority_read_restores_privilege_and_disposes_on_restore_failure(tmp_path, case):
    source = tmp_path / "inert.json"
    source.write_bytes(b"private fixture")
    result = powershell(FUNCTIONS + r"""
$calls = New-Object 'Collections.Generic.List[string]'
$script:opened = $null
function Initialize-PilotBackupInterop {}
function Enable-PilotBackupPrivilege {
    $calls.Add('enable')
    if ($env:PILOT_CASE -eq 'privilege_unavailable') { throw 'authority_backup_privilege_unavailable' }
    @{ previous_enabled = $false }
}
function Open-PilotAuthorityHandle([string]$Path) {
    $calls.Add('read')
    if ($env:PILOT_CASE -eq 'read_failure') { throw 'authority_unreadable' }
    if ($env:PILOT_CASE -eq 'missing') { return $null }
    $script:opened = [IO.File]::OpenRead($env:PILOT_FIXTURE)
    $script:opened
}
function Restore-PilotBackupPrivilege($Context) {
    $calls.Add('restore')
    if ($env:PILOT_CASE -eq 'restore_failure') { throw 'authority_privilege_restore_failed' }
}
$canonical = [IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'), 'openems\https\authority.json')
$errorCategory = $null
$value = $null
try { $value = Open-PilotAuthorityRead $canonical } catch { $errorCategory = $_.Exception.Message }
$readable = $null
if ($null -ne $script:opened) { $readable = $script:opened.CanRead }
if ($null -ne $value) { $value.Dispose() }
@{ calls = @($calls.ToArray()); error_category = $errorCategory; readable_before_caller_dispose = $readable; returned_stream = ($null -ne $value) } | ConvertTo-Json -Depth 4
""", PILOT_CASE=case, PILOT_FIXTURE=str(source))
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    expected = ["enable"] if case == "privilege_unavailable" else ["enable", "read", "restore"]
    assert value["calls"] == expected
    errors = {
        "success": None, "missing": None, "read_failure": "authority_unreadable",
        "privilege_unavailable": "authority_backup_privilege_unavailable",
        "restore_failure": "authority_privilege_restore_failed",
    }
    assert value["error_category"] == errors[case]
    assert value["returned_stream"] is (case == "success")
    if case in {"success", "restore_failure"}:
        assert value["readable_before_caller_dispose"] is (case == "success")


@pytest.mark.parametrize(("tls", "present", "error"), [
    (True, True, None), (False, True, None), (False, False, None),
    (True, False, "authority_missing"),
])
def test_authority_snapshot_preserves_existing_files_and_requires_ca_with_tls(tmp_path, tls, present, error):
    source = tmp_path / "fixture.json"
    source.write_bytes(b"inert protected bytes")
    destination = tmp_path / "backup.json"
    result = powershell(FUNCTIONS + r"""
$script:reads = 0
function Open-PilotAuthorityRead([string]$Path) {
    $script:reads++
    if ($env:PILOT_PRESENT -eq 'yes') { [IO.File]::OpenRead($env:PILOT_FIXTURE) }
}
$config = [pscustomobject]@{
    block_page_https = ($env:PILOT_TLS -eq 'yes')
    authority_path = [IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'), 'openems\https\authority.json')
}
$errorCategory = $null
$result = $null
try {
    $result = Save-PilotAuthority -Config $config -Destination $env:PILOT_DESTINATION
    if ($null -ne $result.file) { Assert-PilotFilesUnchanged @($result.file) }
} catch { $errorCategory = $_.Exception.Message }
@{ error_category = $errorCategory; reads = $script:reads; has_file = ($null -ne $result -and $null -ne $result.file); absent = ($null -ne $result -and $null -ne $result.absent) } | ConvertTo-Json
""", PILOT_PRESENT="yes" if present else "no", PILOT_TLS="yes" if tls else "no",
                        PILOT_FIXTURE=str(source), PILOT_DESTINATION=str(destination))
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    assert value["error_category"] == error
    assert value["has_file"] is present
    assert value["absent"] is (not present and not tls)
    if present:
        assert value["reads"] == 3, "Presence, stable copy and final revalidation must use the protected reader."
        assert destination.read_bytes() == source.read_bytes()
    else:
        assert not destination.exists()


def test_backup_interop_compiles_and_requests_read_only_scoped_handles():
    result = powershell(FUNCTIONS + r"""
Initialize-PilotBackupInterop
@{ compiled = ($null -ne ('OpenEms.PilotAuthorityBackup' -as [type])) } | ConvertTo-Json
""")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"compiled": True}
    source = SCRIPT.read_text(encoding="utf-8")
    for required in ("SeBackupPrivilege", "ERROR_NOT_ALL_ASSIGNED", "GetFileInformationByHandle",
                     "GetFinalPathNameByHandle", "FILE_FLAG_BACKUP_SEMANTICS", "FILE_FLAG_OPEN_REPARSE_POINT",
                     "GENERIC_READ", "FILE_SHARE_READ", "OPEN_EXISTING"):
        assert required in source
    for forbidden in ("SeRestorePrivilege", "SeTakeOwnershipPrivilege", "WRITE_DAC", "WRITE_OWNER", "GENERIC_WRITE"):
        assert forbidden not in source


@pytest.mark.parametrize("tls", [True, False])
def test_authority_access_denied_is_never_treated_as_optional(tmp_path, tls):
    result = powershell(FUNCTIONS + r"""
function Open-PilotAuthorityRead([string]$Path) { throw 'authority_unreadable' }
$config = [pscustomobject]@{ block_page_https = ($env:PILOT_TLS -eq 'yes') }
try { Save-PilotAuthority $config $env:PILOT_DESTINATION; throw 'denied authority accepted' }
catch { $_.Exception.Message }
""", PILOT_TLS="yes" if tls else "no", PILOT_DESTINATION=str(tmp_path / "backup.json"))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "authority_unreadable"
    assert not list(tmp_path.iterdir())


def test_native_authority_reader_rejects_other_paths_before_file_access(tmp_path):
    result = powershell(FUNCTIONS + r"""
Initialize-PilotBackupInterop
try { [OpenEms.PilotAuthorityBackup]::OpenAuthority($env:PILOT_SOURCE); throw 'outside path accepted' }
catch { $_.Exception.GetBaseException().Message }
""", PILOT_SOURCE=str(tmp_path / "absent.json"))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "authority_path_untrusted"


def test_absent_authority_revalidation_uses_protected_reader():
    result = powershell(FUNCTIONS + r"""
$script:reads = 0
function Open-PilotAuthorityRead([string]$Path) { $script:reads++; New-Object IO.MemoryStream }
try { Assert-PilotAuthorityAbsent 'canonical fixture'; throw 'new authority accepted' }
catch { @{ error = $_.Exception.Message; reads = $script:reads } | ConvertTo-Json }
""")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"error": "source_changed", "reads": 1}


@pytest.mark.parametrize("protected", [True, False])
def test_protected_copy_uses_handle_validation_while_common_copy_keeps_path_guard(tmp_path, protected):
    source = tmp_path / "fixture.json"
    source.write_bytes(b"inert fixture")
    destination = tmp_path / "backup.json"
    result = powershell(FUNCTIONS + r"""
$script:guards = 0
function Assert-PilotNoReparse([string]$Path) { $script:guards++; throw 'ordinary_guard_access_denied' }
function Open-PilotAuthorityRead([string]$Path) { [IO.File]::OpenRead($env:PILOT_FIXTURE) }
$errorCategory = $null
try { $record = Copy-PilotFile $env:PILOT_FIXTURE $env:PILOT_DESTINATION -ProtectedAuthority:($env:PILOT_PROTECTED -eq 'yes') }
catch { $errorCategory = $_.Exception.Message }
@{ guards = $script:guards; error = $errorCategory } | ConvertTo-Json
""", PILOT_FIXTURE=str(source), PILOT_DESTINATION=str(destination), PILOT_PROTECTED="yes" if protected else "no")
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    expected = {"guards": 0, "error": None} if protected else {
        "guards": 1, "error": "ordinary_guard_access_denied",
    }
    assert value == expected
    assert destination.exists() is protected
    if protected:
        assert destination.read_bytes() == source.read_bytes()


REGISTRY_PATHS = [
    r"SOFTWARE\Policies\Google\Chrome",
    r"SOFTWARE\Policies\Microsoft\Edge",
    r"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS",
    r"SOFTWARE\Policies\Mozilla\Firefox\Certificates",
    r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
    r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
    r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig",
    r"SYSTEM\CurrentControlSet\Services\openems-agent",
    r"SYSTEM\CurrentControlSet\Services\USBSTOR",
]

REGISTRY_FIXTURE = r"""
$script:registryCalls = New-Object 'Collections.Generic.List[object]'
function New-RegistryFixtureKey([string]$Path, [bool]$Nested = $false) {
    $key = [pscustomobject]@{ Path = $Path; Nested = $Nested }
    $key | Add-Member ScriptMethod GetValueNames {
        if ($env:PILOT_REGISTRY_FAILURE -eq 'enumerate') { throw 'fixture_enumerate_denied' }
        @('FixtureValue')
    }
    $key | Add-Member ScriptMethod GetValueKind { param($Name) 'String' }
    $key | Add-Member ScriptMethod GetValue {
        param($Name, $Fallback, $Options)
        if ($env:PILOT_REGISTRY_FAILURE -eq 'value') { throw 'fixture_value_denied' }
        'inert value'
    }
    $key | Add-Member ScriptMethod GetSubKeyNames { if (-not $this.Nested) { @('Nested') } }
    $key | Add-Member ScriptMethod OpenSubKey {
        param($Name, $Writable)
        if ($Writable) { throw 'writable key requested' }
        if ($env:PILOT_REGISTRY_FAILURE -eq 'child') { throw 'fixture_child_denied' }
        New-RegistryFixtureKey ($this.Path + '\' + $Name) $true
    }
    $key | Add-Member ScriptMethod Dispose {}
    $key
}
function Open-PilotRegistryBase([string]$Hive, [string]$View) {
    if ($env:PILOT_REGISTRY_FAILURE -eq 'base') { throw 'fixture_base_denied' }
    $base = [pscustomobject]@{ Hive = $Hive; View = $View }
    $base | Add-Member ScriptMethod OpenSubKey {
        param($Lookup, $Writable)
        $script:registryCalls.Add(@{ hive = $this.Hive; view = $this.View; lookup = $Lookup; writable = $Writable })
        if ($Lookup -match '(?i)IPSec' -or $Lookup -eq 'SOFTWARE\Policies') { throw 'unrelated protected policy traversed' }
        if ($Writable) { throw 'writable key requested' }
        if ($env:PILOT_REGISTRY_FAILURE -eq 'root') { throw 'fixture_root_denied' }
        if ($Lookup.EndsWith('\USBSTOR')) { return $null }
        New-RegistryFixtureKey $Lookup
    }
    $base | Add-Member ScriptMethod Dispose {}
    $base
}
"""


def registry_fixture(command: str, **environment: str):
    # Redirect the old static open in memory so the RED phase never reads the host registry.
    source = SCRIPT.read_text(encoding="utf-8")
    static_open = "[Microsoft.Win32.RegistryKey]::OpenBaseKey($baseHive, [Microsoft.Win32.RegistryView]::$view)"
    assert static_open in source or "function Open-PilotRegistryBase(" in source
    redirect = r"""
$definition = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-PilotRegistrySnapshot' }, $false)[0].Extent.Text
$definition = $definition.Replace('[Microsoft.Win32.RegistryKey]::OpenBaseKey($baseHive, [Microsoft.Win32.RegistryView]::$view)', '(Open-PilotRegistryBase -Hive $baseHive -View $view)')
. ([scriptblock]::Create($definition))
"""
    return powershell(FUNCTIONS + REGISTRY_FIXTURE + redirect + command, **environment)


def test_registry_backup_covers_agent_subtrees_both_views_and_original_user_without_ipsec():
    result = registry_fixture(r"""
$snapshot = Get-PilotRegistrySnapshot -OriginalUserSid 'S-1-5-21-100'
@{ calls = @($script:registryCalls.ToArray()); snapshot = $snapshot } | ConvertTo-Json -Depth 100
""")
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    expected_calls = [
        {"hive": hive, "view": view, "lookup": prefix + path, "writable": False}
        for hive, prefix in [("LocalMachine", ""), ("Users", "S-1-5-21-100\\")]
        for view in ["Registry64", "Registry32"]
        for path in REGISTRY_PATHS
    ]
    assert value["calls"] == expected_calls
    expected_keys = {
        f"{hive}/{view}/{path}"
        for hive in ["LocalMachine", "CurrentUser"]
        for view in ["Registry64", "Registry32"]
        for path in REGISTRY_PATHS
    }
    assert set(value["snapshot"]) == expected_keys
    for key, tree in value["snapshot"].items():
        if key.endswith(r"\USBSTOR"):
            assert tree is None, "Missing scoped keys must remain explicit in the snapshot."
        else:
            assert tree["values"] == {"FixtureValue": {"kind": "String", "value": "inert value"}}
            assert tree["children"]["Nested"]["values"] == tree["values"]


@pytest.mark.parametrize("phase", ["base", "root", "enumerate", "value", "child"])
def test_registry_errors_inside_allowlist_are_never_omitted(phase):
    result = registry_fixture(r"""
try { $null = Get-PilotRegistrySnapshot -OriginalUserSid 'S-1-5-21-100'; throw 'incomplete snapshot accepted' }
catch { $_.Exception.GetBaseException().Message }
""", PILOT_REGISTRY_FAILURE=phase)
    assert result.returncode == 0, result.stderr
    assert f"fixture_{phase}_denied" in result.stdout
    assert "incomplete snapshot accepted" not in result.stdout


def test_registry_scope_contains_all_current_direct_writer_paths():
    import re

    browser = (ROOT / "agent-rs/src/browser_policy.rs").read_text(encoding="utf-8")
    usb = (ROOT / "deploy/agent-usb.ps1").read_text(encoding="utf-8")
    nrpt = (ROOT / "agent-rs/src/nrpt.rs").read_text(encoding="utf-8")
    writer_paths = set(re.findall(r'r"(SOFTWARE\\Policies\\[^"\n]+)"', browser))
    writer_paths.update(re.findall(r"\$restriction = 'HKLM:\\([^'\n]+)'", usb))
    writer_paths.update(re.findall(r'wide\(r"(SYSTEM\\[^"\n]+DnsPolicyConfig)"\)', nrpt))
    assert len(writer_paths) == 6
    assert writer_paths <= set(REGISTRY_PATHS)
    source = SCRIPT.read_text(encoding="utf-8")
    for path in REGISTRY_PATHS:
        assert f"'{path}'" in source
