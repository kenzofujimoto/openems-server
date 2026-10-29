"""Test only the loopback fixture server; never run the controls harness on the host."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
pytestmark = [pytest.mark.windows_only, pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell 5.1")]

DRIVER = r"""param([string]$Source,[string]$WorkDirectory)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$tokens=$null;$parseErrors=$null
$tree=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count) { throw 'Harness source did not parse.' }
$definition=$tree.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Start-Backend'},$true)
if($null -eq $definition) { throw 'Start-Backend missing.' }
# Load this definition only; no top-level harness code, agent, MSI or OS control.
. ([scriptblock]::Create($definition.Extent.Text))
function Wait-Until([scriptblock]$Condition,[int]$Seconds,[string]$Message) {
    $until=[DateTime]::UtcNow.AddSeconds($Seconds)
    while([DateTime]::UtcNow -lt $until) { if(& $Condition) { return }; Start-Sleep -Milliseconds 100 }
    throw $Message
}
$work=$WorkDirectory
$policy=Join-Path $work 'policy.json'
[IO.File]::WriteAllText($policy,'{"version":1,"digest":"fixture","body":{}}')
$reservation=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
$reservation.Start();$port=$reservation.LocalEndpoint.Port;$reservation.Stop()
$origin='http://127.0.0.1:'+$port
$api=$origin+'/fct/api/public/v1/'
function Send([string]$Route,[string]$Method='GET',[string]$Body=$null,[bool]$Authorized=$true) {
    $request=[Net.HttpWebRequest]::Create($api+$Route+'/')
    $request.Method=$Method;$request.Proxy=$null;$request.KeepAlive=$false;$request.Timeout=10000
    if($Authorized) { $request.Headers['Authorization']='Bearer sandbox-fixture-only' }
    try {
        if($Method -ne 'GET') {
            $bytes=[Text.Encoding]::UTF8.GetBytes($Body);$request.ContentType='application/json'
            $stream=$request.GetRequestStream();try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
        }
        $response=$request.GetResponse()
    }
    catch [Net.WebException] {
        if($null -eq $_.Exception.Response) { return [ordered]@{status=$null;text=$null;error=$_.Exception.Status.ToString()} }
        $response=$_.Exception.Response
    }
    try {
        $reader=New-Object IO.StreamReader($response.GetResponseStream())
        try { $text=$reader.ReadToEnd() } finally { $reader.Dispose() }
        return [ordered]@{status=[int]$response.StatusCode;text=$text;error=$null}
    } finally { $response.Close() }
}
function Abort-Upload {
    $client=New-Object Net.Sockets.TcpClient;$client.Connect('127.0.0.1',$port)
    $client.Client.LingerState=New-Object Net.Sockets.LingerOption($true,0)
    $head="POST /fct/api/public/v1/config/ack/ HTTP/1.1`r`nHost: 127.0.0.1`r`nAuthorization: Bearer sandbox-fixture-only`r`nContent-Length: 100000`r`n`r`n{""secret-body-marker"":"
    $bytes=[Text.Encoding]::ASCII.GetBytes($head);$client.GetStream().Write($bytes,0,$bytes.Length)
    Start-Sleep -Milliseconds 300;$client.Close();Start-Sleep -Seconds 2
}
$job=$null;$observed=[ordered]@{}
try {
    $job=Start-Backend
    $observed.first=Send 'config/assigned'
    Abort-Upload
    $observed.after_abort=Send 'config/assigned'
    Move-Item -LiteralPath $policy -Destination ($policy+'.hidden')
    $observed.route_failure=Send 'config/assigned'
    Move-Item -LiteralPath ($policy+'.hidden') -Destination $policy
    $observed.after_route_failure=Send 'config/assigned'
    $observed.unauthorized=Send 'config/assigned' -Authorized $false
    $observed.register=Send 'register' 'POST' '{}' $false
    $observed.ack=Send 'config/ack' 'POST' "{`"version`":1,`"digest`":`"fixture`",`"success`":true}"
    $observed.unknown=Send 'not-a-route'
    $observed.job_state=[string]$job.State
} finally { if($job) { Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue } }
$observed.engine=$PSVersionTable.PSVersion.Major
$observed | ConvertTo-Json -Depth 6 -Compress
"""


@pytest.fixture(scope="module")
def observed(tmp_path_factory):
    work = tmp_path_factory.mktemp("fixture-backend")
    driver = work.parent / "fixture-backend-driver.ps1"
    driver.write_text(DRIVER, encoding="utf-8-sig")
    result = subprocess.run([
        str(POWERSHELL), "-NoProfile", "-NonInteractive", "-File", str(driver),
        "-Source", str(ROOT / "deploy/test-controls-sandbox.ps1"), "-WorkDirectory", str(work),
    ], capture_output=True, encoding="utf-8", timeout=120, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    return work, json.loads(result.stdout.lstrip("\ufeff"))


def _policy(response):
    assert response["status"] == 200, response
    return json.loads(response["text"])


def test_fixture_backend_keeps_serving_after_an_aborted_upload(observed):
    _, results = observed
    assert results["engine"] == 5
    assert _policy(results["first"])["version"] == 1
    assert _policy(results["after_abort"])["version"] == 1
    assert results["job_state"] == "Running"


def test_fixture_backend_answers_500_for_a_failed_route_and_keeps_serving(observed):
    _, results = observed
    assert results["route_failure"]["status"] == 500
    assert _policy(results["after_route_failure"])["version"] == 1


def test_fixture_backend_preserves_existing_routes_and_authorization(observed):
    work, results = observed
    assert results["unauthorized"]["status"] == 403
    assert json.loads(results["register"]["text"]) == {"client_id": "sandbox-controls", "device_token": "sandbox-fixture-only"}
    assert results["ack"]["status"] == 200
    assert results["unknown"]["status"] == 404
    acks = [json.loads(line) for line in (work / "ack.log").read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    assert acks == [{"version": 1, "digest": "fixture", "success": True}]


def test_fixture_backend_traces_every_request_without_secrets_or_bodies(observed):
    work, _ = observed
    trace_path = work / "backend-events.log"
    raw = trace_path.read_text(encoding="utf-8-sig")
    assert "sandbox-fixture-only" not in raw and "secret-body-marker" not in raw and "not-a-route" not in raw
    events = [json.loads(line) for line in raw.splitlines() if line.strip()]
    assert {tuple(sorted(event)) for event in events} == {("at_utc", "error_type", "response_written", "route", "status")}
    routes = [(event["route"], event["status"], event["response_written"]) for event in events]
    assert routes[0] == ("config/assigned", 200, True)
    aborted = [event for event in events if event["route"] == "config/ack" and not event["response_written"]]
    assert len(aborted) == 1 and aborted[0]["error_type"]
    failed = [event for event in events if event["route"] == "config/assigned" and event["status"] == 500]
    assert len(failed) == 1 and failed[0]["error_type"]
    assert ("config/assigned", 403, True) in routes and ("register", 200, True) in routes
    assert ("config/ack", 200, True) in routes and ("other", 404, True) in routes
