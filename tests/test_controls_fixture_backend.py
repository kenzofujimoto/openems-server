"""Test only the loopback fixture server; never run the controls harness on the host."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

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
# Load trusted definitions only; never run the harness top level or any control.
foreach($definition in $tree.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) {
    . ([scriptblock]::Create($definition.Extent.Text))
}
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
    # The harness polls ack.log with a shared read handle while the agent posts acknowledgments.
    $reader=[IO.File]::Open((Join-Path $work 'ack.log'),'OpenOrCreate','Read','ReadWrite')
    try {
        $observed.ack_while_read=Send 'config/ack' 'POST' "{`"version`":2,`"digest`":`"fixture`",`"success`":true}"
        $observed.inventory_while_read=$null
        $inventoryReader=[IO.File]::Open((Join-Path $work 'inventory.log'),'OpenOrCreate','Read','ReadWrite')
        try { $observed.inventory_while_read=Send 'inventory' 'POST' '{"applications":[]}' } finally { $inventoryReader.Dispose() }
    } finally { $reader.Dispose() }
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
    assert acks[0] == {"version": 1, "digest": "fixture", "success": True}


def test_fixture_backend_records_acks_while_the_harness_reads_the_log(observed):
    # PS 5.1 Add-Content fails with a sharing violation here, so ACKs were answered 500 and lost.
    work, results = observed
    assert results["ack_while_read"]["status"] == 200, results["ack_while_read"]
    assert results["inventory_while_read"]["status"] == 200, results["inventory_while_read"]
    acks = [json.loads(line) for line in (work / "ack.log").read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    assert acks == [{"version": 1, "digest": "fixture", "success": True}, {"version": 2, "digest": "fixture", "success": True}]
    inventories = [line for line in (work / "inventory.log").read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    assert [json.loads(line) for line in inventories] == [{"applications": []}]


def test_fixture_backend_traces_every_request_without_secrets_or_bodies(observed):
    work, _ = observed
    trace_path = work / "backend-events.log"
    raw = trace_path.read_text(encoding="utf-8-sig")
    assert "sandbox-fixture-only" not in raw and "secret-body-marker" not in raw and "not-a-route" not in raw
    events = [json.loads(line) for line in raw.splitlines() if line.strip()]
    assert {tuple(sorted(event)) for event in events} == {("at_utc", "attempt_id", "authorized", "error_type", "is_probe", "response_written", "route", "status", "trace_write_failures")}
    assert len({event["attempt_id"] for event in events}) == 1
    assert len(events[0]["attempt_id"]) == 32
    assert events[0]["is_probe"] is True and events[0]["authorized"] is True
    routes = [(event["route"], event["status"], event["response_written"]) for event in events]
    assert routes[0] == ("config/assigned", 200, True)
    aborted = [event for event in events if event["route"] == "config/ack" and not event["response_written"]]
    assert len(aborted) == 1 and aborted[0]["error_type"]
    failed = [event for event in events if event["route"] == "config/assigned" and event["status"] == 500]
    assert len(failed) == 1 and failed[0]["error_type"]
    assert ("config/assigned", 403, True) in routes and ("register", 200, True) in routes
    assert ("config/ack", 200, True) in routes and ("other", 404, True) in routes


FUNCTION_DRIVER = r"""param([string]$Source,[string]$WorkDirectory,[string]$Case,[string]$Origin='')
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$tokens=$null;$parseErrors=$null
$tree=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count) { throw 'Harness source did not parse.' }
# This is deliberately not dot-sourcing the harness. Define functions without invoking
# its VM gate, parent observer block, scheduled worker, MSI, agent, PnP or registry code.
foreach($definition in $tree.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) {
    . ([scriptblock]::Create($definition.Extent.Text))
}
$work=$WorkDirectory
$origin=$Origin
$Kind='USB'
$reportName='usb-result.json'
$inputManifest=[pscustomobject]@{source_revision='fixture-revision'}
"""


def _run_functions(tmp_path, body, case, origin=""):
    driver = tmp_path / "extracted-functions.ps1"
    driver.write_text(FUNCTION_DRIVER + body, encoding="utf-8-sig")
    result = subprocess.run([
        str(POWERSHELL), "-NoProfile", "-NonInteractive", "-File", str(driver),
        "-Source", str(ROOT / "deploy/test-controls-sandbox.ps1"),
        "-WorkDirectory", str(tmp_path), "-Case", case, "-Origin", origin,
    ], capture_output=True, encoding="utf-8", timeout=30, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout.lstrip("\ufeff").strip().splitlines()[-1])


JOB_LIFECYCLE_DRIVER = r"""
$script:backend=$null
$script:starts=0;$script:stops=0;$script:removes=0;$script:ownedDuringWait=$false
$script:fakeJob=[pscustomobject]@{Id=41;State='Running';ChildJobs=@([pscustomobject]@{JobStateInfo=[pscustomobject]@{Reason=$null}})}
function Start-Job {
    param($ArgumentList,$ScriptBlock)
    $script:starts++
    return $script:fakeJob
}
function Stop-Job {
    param($Job,$ErrorAction)
    $script:stops++
    if($Case -eq 'teardown_failure') { throw [IO.IOException]::new('private-marker-must-not-leak') }
    $Job.State='Stopped'
}
function Remove-Job {param($Job,[switch]$Force,$ErrorAction) $script:removes++}
function Test-BackendReady {param($Backend,$Deadline) return $true}
function Wait-Until {
    param([scriptblock]$Condition,[int]$Seconds,[string]$Message)
    $script:ownedDuringWait=($script:backend -eq $script:fakeJob)
    if($Case -eq 'read_failure') { throw [UnauthorizedAccessException]::new('private-marker-must-not-leak') }
    throw [TimeoutException]::new('private-marker-must-not-leak')
}
$firstError=$null;$secondError=$null
try { $null=Start-Backend } catch {$firstError=$_.Exception.Message}
$retainedAfterFailure=($script:backend -eq $script:fakeJob)
if($Case -eq 'teardown_failure') {
    try {$null=Start-Backend} catch {$secondError=$_.Exception.Message}
}
@{owned_during_wait=$script:ownedDuringWait;starts=$script:starts;stops=$script:stops;removes=$script:removes;
    retained_after_failure=$retainedAfterFailure;first_error=$firstError;second_error=$secondError}|ConvertTo-Json -Compress
"""


@pytest.mark.parametrize("case,category", [("timeout", "TimeoutException"), ("read_failure", "UnauthorizedAccessException")])
def test_startup_failure_tears_down_the_job_it_owned_during_the_wait(tmp_path, case, category):
    result = _run_functions(tmp_path, JOB_LIFECYCLE_DRIVER, case)
    assert result["owned_during_wait"] is True
    assert (result["starts"], result["stops"], result["removes"]) == (1, 1, 1)
    assert result["retained_after_failure"] is False
    assert category in result["first_error"] and "private-marker" not in result["first_error"]


def test_failed_teardown_retains_ownership_and_prevents_an_overlapping_start(tmp_path):
    result = _run_functions(tmp_path, JOB_LIFECYCLE_DRIVER, "teardown_failure")
    assert result["retained_after_failure"] is True
    assert result["starts"] == 1 and result["removes"] == 0
    assert "TimeoutException" in result["first_error"]
    assert result["second_error"] and "private-marker" not in result["first_error"] + result["second_error"]


READY_DRIVER = r"""
$attempt='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
$ready=Join-Path $work ('backend-ready-'+$attempt+'.json')
$receipt=@{attempt_id=$attempt;pid=31415}
if($Case -eq 'old_nonce') {$receipt.attempt_id='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'}
if($Case -eq 'invalid_pid') {$receipt.pid=0}
if($Case -eq 'wrong_pid') {$receipt.pid=27182}
$receipt|ConvertTo-Json -Compress|Set-Content -LiteralPath $ready -Encoding UTF8
[IO.File]::WriteAllText((Join-Path $work 'policy.json'),' {"version":1,"digest":"fixture","body":{}} ')
$job=[pscustomobject]@{State='Running';BackendAttemptId=$attempt;BackendStartedUtc=[DateTime]::UtcNow.AddMinutes(-1);
    BackendReadyPath=$ready;BackendProcessId=31415}
$accepted=Test-BackendReady -Backend $job -Deadline ([DateTime]::UtcNow.AddSeconds(5))
@{accepted=[bool]$accepted}|ConvertTo-Json -Compress
"""


@pytest.mark.parametrize("case,expected", [
    ("valid", True), ("old_nonce", False), ("invalid_pid", False), ("wrong_pid", False),
    ("wrong_header", False), ("wrong_version", False), ("wrong_digest", False),
])
def test_ready_receipt_requires_current_nonce_pid_and_authenticated_http_identity(tmp_path, case, expected):
    observed = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            observed.append({"authorization": self.headers.get("Authorization"),
                             "probe": self.headers.get("X-Openems-Fixture-Probe")})
            body = json.dumps({"version": 2 if case == "wrong_version" else 1,
                               "digest": "other" if case == "wrong_digest" else "fixture", "body": {}}).encode()
            self.send_response(200)
            self.send_header("X-Openems-Fixture-Attempt", "b" * 32 if case == "wrong_header" else "a" * 32)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = _run_functions(tmp_path, READY_DRIVER, case, f"http://127.0.0.1:{server.server_port}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert result["accepted"] is expected
    if expected:
        assert observed == [{"authorization": "Bearer sandbox-fixture-only", "probe": "a" * 32}]
    if case in {"old_nonce", "invalid_pid", "wrong_pid"}:
        assert observed == []


CONTACT_DRIVER = r"""
$attempt='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
$since=[DateTime]::UtcNow.AddMinutes(-1)
$job=[pscustomobject]@{State='Running';BackendAttemptId=$attempt;BackendStartedUtc=$since;BackendReadyPath=(Join-Path $work 'unused-ready')}
$valid=@{at_utc=$since.AddSeconds(1).ToString('o');attempt_id=$attempt;route='messages/pull';status=200;
    response_written=$true;is_probe=$false;authorized=$true;error_type=$null;trace_write_failures=0}
$invalid=@{};foreach($key in $valid.Keys) {$invalid[$key]=$valid[$key]}
switch($Case) {
    'probe' {$invalid.is_probe=$true}
    'old_attempt' {$invalid.attempt_id='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'}
    'old_time' {$invalid.at_utc=$since.AddSeconds(-1).ToString('o')}
    'old_contact' {$invalid.at_utc=$since.AddSeconds(1).ToString('o')}
    'unauthorized' {$invalid.authorized=$false}
    'http_failure' {$invalid.status=500}
    'aborted' {$invalid.response_written=$false}
    'other_route' {$invalid.route='inventory'}
}
$script:reads=0;$script:seconds=$null;$script:rows=@($invalid)
function Read-Rows {
    param($Name)
    $script:reads++
    if($Case -notin @('old_time','old_contact')) {foreach($row in $script:rows){$row.at_utc=[DateTime]::UtcNow.ToString('o')}}
    return $script:rows
}
function Wait-Until {
    param([scriptblock]$Condition,[int]$Seconds,[string]$Message)
    $script:seconds=$Seconds
    if(& $Condition) {return}
    if($Case -eq 'delayed') {$script:rows=@($valid);if(& $Condition){return}}
    throw [TimeoutException]::new('no current authenticated contact')
}
if($Case -eq 'delayed') {$invalid.is_probe=$true;$script:rows=@($invalid)}
$accepted=$false
try {$null=Wait-BackendContact -Backend $job -Seconds 360;$accepted=$true} catch {}
@{accepted=$accepted;reads=$script:reads;seconds=$script:seconds}|ConvertTo-Json -Compress
"""


@pytest.mark.parametrize("case", ["probe", "old_attempt", "old_time", "old_contact", "unauthorized", "http_failure", "aborted", "other_route"])
def test_reconnect_does_not_count_probe_historical_or_failed_requests(tmp_path, case):
    result = _run_functions(tmp_path, CONTACT_DRIVER, case)
    assert result["accepted"] is False and result["reads"] >= 1
    assert result["seconds"] == 360


def test_reconnect_waits_for_real_contact_after_a_probe_without_changing_its_bound(tmp_path):
    result = _run_functions(tmp_path, CONTACT_DRIVER, "delayed")
    assert result == {"accepted": True, "reads": 2, "seconds": 360}


OBSERVER_DRIVER = r"""
$resultPath=Join-Path $work 'usb-result.json'
$terminal=@{kind='USB';worker_id='openems-controls-fixture';status='passed';passed=$true;
    automation_passed=$true;physical_acceptance_pending=$false;checks=@();pending=@();cleanup_errors=@();
    started_utc=[DateTime]::UtcNow.AddSeconds(-10).ToString('o');finished_utc=[DateTime]::UtcNow.ToString('o');
    package_receipt=@{source_revision='fixture-revision'}}
switch($Case) {
    'wrong_kind' {$terminal.kind='Applications'}
    'wrong_worker' {$terminal.worker_id='openems-controls-old'}
    'wrong_revision' {$terminal.package_receipt.source_revision='older-revision'}
    'missing_finished' {$terminal.Remove('finished_utc')}
    'invalid_status' {$terminal.status='unexpected'}
    'running' {$terminal.status='running';$terminal.Remove('finished_utc')}
}
$terminal|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $resultPath -Encoding UTF8
$script:unregistered=0;$script:exported=0;$script:exportAttempts=0;$script:readCalls=0;$script:order=@()
function Read-ControlText {
    param($Path)
    $script:readCalls++
    if($Case -eq 'read_error') {throw [UnauthorizedAccessException]::new('bounded read failure')}
    return [IO.File]::ReadAllText($Path)
}
function Write-Json {
    param($Path,$Value,[switch]$SharedFolder)
    $script:exportAttempts++
    if($Case -eq 'export_error') {throw [IO.IOException]::new('shared folder unavailable')}
    $script:exported++;$script:order+=@('export')
}
function Get-ScheduledTask {
    param($TaskName,$ErrorAction)
    return [pscustomobject]@{State=$(if($Case -eq 'terminal_running'){'Running'}else{'Ready'})}
}
function Unregister-ScheduledTask {
    param($TaskName,$Confirm,$ErrorAction)
    $script:unregistered++;$script:order+=@('unregister')
}
function Start-Sleep {param($Milliseconds,$Seconds)}
$deadline=[DateTime]::UtcNow.AddMilliseconds(150)
if($Case -eq 'deadline') {$deadline=[DateTime]::UtcNow.AddSeconds(-1)}
$returned=$false;$errorType=$null
try {
    $outcome=Observe-ControlsResult -ResultPath $resultPath -TaskName 'fixture-task' -Destination (Join-Path $work 'export.json') `
        -Deadline $deadline -ExpectedWorkerId 'openems-controls-fixture' -ExpectedKind 'USB' -ExpectedRevision 'fixture-revision'
    $returned=$null -ne $outcome
} catch {$errorType=$_.Exception.GetType().Name}
@{returned=$returned;unregistered=$script:unregistered;exported=$script:exported;export_attempts=$script:exportAttempts;
    read_calls=$script:readCalls;order=$script:order;error_type=$errorType}|ConvertTo-Json -Compress
"""


@pytest.mark.parametrize("case", ["read_error", "export_error", "deadline", "wrong_kind", "wrong_worker", "wrong_revision", "missing_finished", "invalid_status", "running"])
def test_observer_preserves_worker_task_without_a_verified_exported_terminal(tmp_path, case):
    result = _run_functions(tmp_path, OBSERVER_DRIVER, case)
    assert result["returned"] is False
    assert result["unregistered"] == 0
    assert result["error_type"] != "CommandNotFoundException"
    if case != "deadline":
        assert result["read_calls"] >= 1
    if case == "export_error":
        assert result["export_attempts"] == 1


def test_observer_keeps_a_still_running_task_after_exporting_its_terminal(tmp_path):
    result = _run_functions(tmp_path, OBSERVER_DRIVER, "terminal_running")
    assert result["returned"] is True and result["exported"] == 1
    assert result["unregistered"] == 0


def test_observer_unregisters_an_exited_worker_only_after_exporting_its_valid_terminal(tmp_path):
    result = _run_functions(tmp_path, OBSERVER_DRIVER, "terminal_ready")
    assert result["returned"] is True and result["error_type"] is None
    assert result["order"] == ["export", "unregister"] and result["unregistered"] == 1


ACK_DRIVER = r"""
$assignment=@{version=5;digest=('ab'*32)}
$script:rows=@(@{version=5;digest=$assignment.digest;success=$false})
$script:bounds=@();$script:samples=0
function Read-Rows {param($Name) $script:samples++;return $script:rows}
function Wait-Until {
    param([scriptblock]$Condition,[int]$Seconds,[string]$Message)
    $script:bounds+=@($Seconds)
    if(& $Condition){return}
    if($Case -eq 'eventual_positive') {$script:rows=@(@{version=5;digest=$assignment.digest;success=$true});if(& $Condition){return}}
    throw [TimeoutException]::new('no matching positive ACK')
}
$accepted=$false
try {$null=Wait-Ack $assignment;$accepted=$true} catch {}
@{accepted=$accepted;bounds=$script:bounds;samples=$script:samples}|ConvertTo-Json -Compress
"""


@pytest.mark.parametrize("case,accepted", [("eventual_positive", True), ("negative_only", False)])
def test_ack_retries_within_one_unchanged_ninety_second_window(tmp_path, case, accepted):
    result = _run_functions(tmp_path, ACK_DRIVER, case)
    assert result["accepted"] is accepted and result["bounds"] == [90]


def test_usb_restart_and_fallback_cleanup_observe_reconnect_before_release_publication():
    source = (ROOT / "deploy/test-controls-sandbox.ps1").read_text(encoding="utf-8-sig")
    restarted = source.split("Record-Check 'offline restart retained the storage policy and healthy HID devices'", 1)[1].split("if ($PhysicalDrive)", 1)[0]
    cleanup = source.rsplit("if ($installed)", 1)[1]
    for block in (restarted, cleanup):
        assert block.index("Wait-BackendContact") < block.index("Publish-Body (Empty-Body)")
