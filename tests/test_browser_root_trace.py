"""Exercise diagnostic parsing with synthetic exports and event records."""

from __future__ import annotations

import base64
import os
from pathlib import Path
import shutil
import subprocess

import pytest

TRACE_HELPER = Path(__file__).resolve().parents[1] / "deploy/browser_root_trace.ps1"
pytestmark = [
    pytest.mark.windows_only,
    pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell diagnostic contracts"),
]


@pytest.mark.parametrize("case", [
    pytest.param(r"""
$rows=@(
    ('"4:08:12.1234567 PM","svchost.exe","78","RegSetValue","HKLM\Software\Microsoft\SystemCertificates\AuthRoot\Certificates\' + $a.ToLowerInvariant() + '\Blob","SUCCESS","Data: fixture, private"')
    ('"16:08:12.125","firefox.exe","1450","RegCreateKey","HKU\S-1-5-21-123\Software\Microsoft\SystemCertificates\ROOT\Certificates\' + $b + '","SUCCESS","Disposition: REG_CREATED_NEW_KEY"')
    ('"16:08:12.126","agent.exe","1460","RegSetValue","HKCU\Software\Policies\Microsoft\SystemCertificates\Root\Certificates\' + $a + '\Blob","SUCCESS","Type: REG_BINARY"')
    ('"16:08:12.127","agent.exe","1460","RegCreateKey","HKLM\Software\Microsoft\SystemCertificates\ROOT\Certificates\' + $a + '","SUCCESS","Disposition: REG_OPENED_EXISTING_KEY"')
    ('"16:08:12.128","agent.exe","1460","RegQueryValue","HKLM\Software\Microsoft\SystemCertificates\ROOT\Certificates\' + $a + '\Blob","SUCCESS",""')
    ('"16:08:12.129","agent.exe","1460","RegSetValue","HKLM\Software\Microsoft\SystemCertificates\ROOT\Certificates\' + $a + '\Blob","ACCESS DENIED",""')
    ('"16:08:12.130","agent.exe","1460","RegSetValue","HKLM\Software\Microsoft\SystemCertificates\CA\Certificates\' + $a + '\Blob","SUCCESS",""')
    ('"16:08:12.131","agent.exe","1460","RegSetValue","HKLM\Software\Microsoft\SystemCertificates\ROOT\Certificates\C' + $a + '\Blob","SUCCESS",""')
)
Write-Csv $rows
$result=Read-BrowserRootProcmonCsv -LiteralPath $csvPath -Thumbprints @($a,$b)
Assert-Equal 8 $result.rows_scanned
Assert-Equal 3 $result.writes.Count
$first=$result.writes[0]
Assert-Equal 'svchost.exe' $first.process_name
Assert-Equal 78 $first.pid
Assert-Equal '16:08:12.1234567' $first.time_of_day_iso
Assert-Equal '4:08:12.1234567 PM' $first.time_of_day
Assert-Equal 'RegSetValue' $first.operation
Assert-Equal 'authroot' $first.store
Assert-Equal 'local_machine' $first.registry_scope
Assert-Equal ('HKLM\Software\Microsoft\SystemCertificates\AuthRoot\Certificates\' + $a.ToLowerInvariant() + '\Blob') $first.registry_path
Assert-Equal $a $first.thumbprint
Assert-Equal 'value_set' $first.write_kind
Assert-Equal 'key_created' $result.writes[1].write_kind
Assert-Equal 'user' $result.writes[1].registry_scope
Assert-Equal 'user' $result.writes[2].registry_scope
Assert-Equal 'root' $result.writes[2].store
Assert-Equal $false (($result | ConvertTo-Json -Depth 8).Contains('fixture, private'))
""", id="attributes-successful-root-writes"),
    pytest.param(r"""
Write-Csv @()
$result=Read-BrowserRootProcmonCsv -LiteralPath $csvPath -Thumbprints @($a,$b)
Assert-Equal 0 $result.rows_scanned
Assert-Equal 0 $result.writes.Count

'invalid header' | Set-Content -LiteralPath $csvPath -Encoding utf8
Assert-Rejected { Read-BrowserRootProcmonCsv -LiteralPath $csvPath -Thumbprints @($a,$b) } 'header'
Write-Csv @() ($header + ',"PID"')
Assert-Rejected { Read-BrowserRootProcmonCsv -LiteralPath $csvPath -Thumbprints @($a,$b) } 'header'
Write-Csv @('"invalid", "column count"')
Assert-Rejected { Read-BrowserRootProcmonCsv -LiteralPath $csvPath -Thumbprints @($a,$b) } 'row'
Write-Csv @('"unterminated')
Assert-Rejected { Read-BrowserRootProcmonCsv -LiteralPath $csvPath -Thumbprints @($a,$b) } 'row'
""", id="distinguishes-empty-data-from-invalid-csv"),
    pytest.param(r"""
$row='"16:08:12.130","agent.exe","1460","RegSetValue","HKLM\Software\Microsoft\SystemCertificates\ROOT\Certificates\' + $a + '\Blob","SUCCESS",""'
Write-Csv @($row,$row)
Assert-Rejected { Read-BrowserRootProcmonCsv -LiteralPath $csvPath -Thumbprints @($a,$b) -MaxRows 1 } 'row limit'
Assert-Rejected { Read-BrowserRootProcmonCsv -LiteralPath $csvPath -Thumbprints @($a,$b) -MaxBytes 100 } 'byte limit'
Assert-Rejected { Read-BrowserRootProcmonCsv -LiteralPath $csvPath -Thumbprints @($a,$a) } 'thumbprint'
Assert-Rejected { Read-BrowserRootProcmonCsv -LiteralPath $csvPath -Thumbprints @('wrong') } 'thumbprint'
Write-Csv @($row.Replace('"1460"','"unknown"'))
Assert-Rejected { Read-BrowserRootProcmonCsv -LiteralPath $csvPath -Thumbprints @($a) } 'identity'
Write-Csv @($row.Replace('"16:08:12.130"','"25:18:19.1"'))
Assert-Rejected { Read-BrowserRootProcmonCsv -LiteralPath $csvPath -Thumbprints @($a) } 'timestamp'
""", id="fails-closed-on-unbounded-or-unattributable-evidence"),
    pytest.param(r"""
$otherHash='C'+$b
$match=New-Event $start.AddSeconds(1).LocalDateTime 10 1870 ('<Chain Thumbprint="' + $a + '" Subject="CN=GlobalSign Root CA, O=GlobalSign" Secret="test-only" />')
$other=New-Event $start.AddSeconds(2).LocalDateTime 11 1872 ('<Chain Thumbprint="' + $otherHash + '" Subject="CN=GlobalSign Root CA - R3" />')
$outside=New-Event $start.AddSeconds(-1).LocalDateTime 12 1873 'intentionally broken XML'
$result=Select-BrowserRootCapi2Events -Events @($other,$match,$outside) -WindowStart $start -WindowEnd $end -Thumbprints @($a,$b) -Subjects @('GlobalSign Root CA','IdenTrust Commercial Root CA 1')
Assert-Equal 2 $result.events_scanned
Assert-Equal 2 $result.events.Count
Assert-Equal 10 $result.events[0].record_id
Assert-Equal 1870 $result.events[0].pid
Assert-Equal 30 $result.events[0].event_id
Assert-Equal @($a) @($result.events[0].matched_thumbprints)
Assert-Equal @('GlobalSign Root CA') @($result.events[0].matched_subjects)
Assert-Equal @() @($result.events[1].matched_thumbprints)
Assert-Equal @() @($result.events[1].matched_subjects)
Assert-Equal $false (($result | ConvertTo-Json -Depth 8).Contains('test-only'))
""", id="keeps-timed-capi2-metadata-and-explicit-root-hints"),
    pytest.param(r"""
$one=New-Event $start.UtcDateTime 10 1870 '<Chain />'
$empty=Select-BrowserRootCapi2Events -Events @() -WindowStart $start -WindowEnd $end -Thumbprints @($a)
Assert-Equal 0 $empty.events_scanned
Assert-Equal 0 $empty.events.Count
Assert-Rejected { Select-BrowserRootCapi2Events -Events @($one) -WindowStart $end -WindowEnd $start -Thumbprints @($a) } 'window'
Assert-Rejected { Select-BrowserRootCapi2Events -Events @($one) -WindowStart $start -WindowEnd $end.AddMinutes(31) -Thumbprints @($a) } 'window'
Assert-Rejected { Select-BrowserRootCapi2Events -Events (@($one)*501) -WindowStart $start -WindowEnd $end -Thumbprints @($a) } 'event limit'
$one.ProviderName='AnotherProvider'
Assert-Rejected { Select-BrowserRootCapi2Events -Events @($one) -WindowStart $start -WindowEnd $end -Thumbprints @($a) } 'channel'
$one.ProviderName='Microsoft-Windows-CAPI2'
$one.Xml='<!DOCTYPE Event [<!ENTITY local "not allowed">]><Event>&local;</Event>'
Assert-Rejected { Select-BrowserRootCapi2Events -Events @($one) -WindowStart $start -WindowEnd $end -Thumbprints @($a) } 'XML'
""", id="rejects-truncated-unscoped-capi2-exports"),
])
def test_root_trace_contract(tmp_path, case):
    assert TRACE_HELPER.is_file(), "diagnostic parsing helper is required"
    powershell = shutil.which("powershell.exe")
    assert powershell, "Windows PowerShell 5.1 is required"
    source = r"""
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null
$errors=$null
$helper='__HELPER__'
$ast=[Management.Automation.Language.Parser]::ParseFile($helper,[ref]$tokens,[ref]$errors)
if ($errors.Count -ne 0) { throw $errors[0].Message }
if ($null -ne $ast.BeginBlock -or $null -ne $ast.ProcessBlock -or
    $null -ne $ast.ParamBlock -or $ast.UsingStatements.Count -ne 0) { throw 'Function-only helper required' }
foreach ($statement in $ast.EndBlock.Statements) {
    if ($statement -isnot [Management.Automation.Language.FunctionDefinitionAst]) { throw 'Function-only helper required' }
}
. $helper
function Assert-Equal($Expected,$Actual) {
    if ((ConvertTo-Json -InputObject $Expected -Compress -Depth 10) -cne
        (ConvertTo-Json -InputObject $Actual -Compress -Depth 10)) {
        throw "Expected $(ConvertTo-Json -InputObject $Expected -Compress); got $(ConvertTo-Json -InputObject $Actual -Compress)"
    }
}
function Assert-Rejected([scriptblock]$Test,[string]$Message) {
    try { & $Test | Out-Null } catch {
        if ($_.Exception.Message -notlike "*$Message*") { throw }
        return
    }
    throw "Expected rejection matching: $Message"
}
function Write-Csv([string[]]$Rows,[string]$HeaderLine=$header) {
    (@($HeaderLine)+$Rows) | Set-Content -LiteralPath $csvPath -Encoding UTF8
}
function New-Event([datetime]$Created,[long]$Record,[int]$Process,[string]$Data) {
    $event=[pscustomobject]@{
        TimeCreated=$Created; RecordId=$Record; Id=30; ProcessId=$Process; ThreadId=4
        LogName='Microsoft-Windows-CAPI2/Operational'; ProviderName='Microsoft-Windows-CAPI2'
        Xml='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System></System><UserData>' + $Data + '</UserData></Event>'
    }
    $event | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.Xml }
    return $event
}
$a='A'*40
$b='B'*40
$csvPath='__CSV__'
$header='"Time of Day","Process Name","PID","Operation","Path","Result","Detail"'
$start=[DateTimeOffset]'2026-11-17T16:08:12Z'
$end=$start.AddMinutes(1)
__CASE__
'trace contract passed'
"""
    source = (
        source.replace("__HELPER__", str(TRACE_HELPER).replace("'", "''"))
        .replace("__CSV__", str(tmp_path / "procmon.csv").replace("'", "''"))
        .replace("__CASE__", case)
    )
    encoded = base64.b64encode(source.encode("utf-16-le")).decode("ascii")
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "trace contract passed" in result.stdout
