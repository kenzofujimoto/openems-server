"""Test only the loopback fixture server; never run the controls harness on the host."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

import pytest
from defusedxml import ElementTree

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
function Remove-Job {
    param($Job,[switch]$Force,$ErrorAction)
    $script:removes++
    if($Case -eq 'remove_failure') {throw [IO.IOException]::new('private-marker-must-not-leak')}
}
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
if($Case -in @('teardown_failure','remove_failure')) {
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


def test_failed_job_removal_retains_the_stopped_handle_and_prevents_an_overlapping_start(tmp_path):
    result = _run_functions(tmp_path, JOB_LIFECYCLE_DRIVER, "remove_failure")
    assert result["retained_after_failure"] is True
    assert result["starts"] == result["stops"] == result["removes"] == 1
    assert "TimeoutException" in result["first_error"] and result["second_error"]
    assert "private-marker" not in result["first_error"] + result["second_error"]


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


def test_ready_health_body_must_finish_inside_the_existing_deadline(tmp_path):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            import time

            body = json.dumps({"version": 1, "digest": "fixture", "body": {}}).encode()
            self.send_response(200)
            self.send_header("X-Openems-Fixture-Attempt", "a" * 32)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            # Every individual read can succeed within 700 ms, while the complete
            # response exceeds that total budget. Per-read timeouts alone fail here.
            edges = [len(body) * index // 4 for index in range(5)]
            try:
                for index in range(4):
                    time.sleep(0.3)
                    self.wfile.write(body[edges[index]:edges[index + 1]])
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                # Deadline cancellation deliberately closes this disposable connection.
                pass

        def log_message(self, *_args):
            pass

    driver = READY_DRIVER.replace(
        "$accepted=Test-BackendReady -Backend $job -Deadline ([DateTime]::UtcNow.AddSeconds(5))",
        "$clock=[Diagnostics.Stopwatch]::StartNew();$accepted=Test-BackendReady -Backend $job -Deadline ([DateTime]::UtcNow.AddMilliseconds(700))",
    ).replace("@{accepted=[bool]$accepted}", "@{accepted=[bool]$accepted;elapsed_ms=$clock.Elapsed.TotalMilliseconds}")
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = _run_functions(tmp_path, driver, "slow_body", f"http://127.0.0.1:{server.server_port}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert result["accepted"] is False
    assert result["elapsed_ms"] < 1050, result


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
    if($Case -eq 'late_read') {Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 750}
    if($Case -eq 'read_error') {throw [UnauthorizedAccessException]::new('bounded read failure')}
    return [IO.File]::ReadAllText($Path)
}
function Write-Json {
    param($Path,$Value,[switch]$SharedFolder)
    $script:exportAttempts++
    if($Case -eq 'late_export') {Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 750}
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
if($Case -in @('late_read','late_export')) {$deadline=[DateTime]::UtcNow.AddMilliseconds(500)}
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


@pytest.mark.parametrize("case", ["late_read", "late_export"])
def test_observer_io_that_crosses_the_global_deadline_preserves_the_worker_task(tmp_path, case):
    result = _run_functions(tmp_path, OBSERVER_DRIVER, case)
    assert result["returned"] is False
    assert result["unregistered"] == 0
    assert result["read_calls"] == 1
    if case == "late_export":
        assert result["export_attempts"] == 1


def test_reconnect_does_not_accept_a_read_that_finishes_after_its_bound(tmp_path):
    body = r"""
$attempt='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
$since=[DateTime]::UtcNow.AddMinutes(-1)
$job=[pscustomobject]@{State='Running';BackendAttemptId=$attempt;BackendStartedUtc=$since}
$script:reads=0
function Read-Rows {
    param($Name)
    $script:reads++
    Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 1200
    return @(@{at_utc=[DateTime]::UtcNow.ToString('o');attempt_id=$attempt;route='messages/pull';status=200;
        response_written=$true;is_probe=$false;authorized=$true;error_type=$null;trace_write_failures=0})
}
$accepted=$false
try {$null=Wait-BackendContact -Backend $job -Seconds 1;$accepted=$true} catch {}
@{accepted=$accepted;reads=$script:reads}|ConvertTo-Json -Compress
"""
    result = _run_functions(tmp_path, body, "late_contact")
    assert result == {"accepted": False, "reads": 1}


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


PROBE_OBSERVATION_DRIVER = r"""
$invoke=$tree.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-Fixture'},$true)[0]
$boundary=@($invoke.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Start-FixtureProcess'},$true))
$staticLaunch=@($invoke.FindAll({param($node) $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Static -and $node.Member.Value -eq 'Start'},$true))
# Refuse to exercise the legacy static process launcher on the development host.
if($boundary.Count -ne 1 -or $staticLaunch.Count -ne 0) { @{boundary_ready=$false}|ConvertTo-Json -Compress; return }
$script:result=[ordered]@{fixture_probes=@();cleanup_errors=@()}
$resultPath=Join-Path $work 'inert-result.json'
$script:waits=@();$script:killed=$false;$script:disposed=$false;$script:starts=0
$script:traceCalls=@()
$launchTraceProfile=if($Case.StartsWith('trace_') -and $Case -ne 'trace_no_profile'){Join-Path $work 'mock-profile.wprp'}else{$null}
$Kind=if($Case -eq 'trace_usb'){'USB'}else{'Applications'}
$probePhase=if($Case -eq 'trace_baseline'){'network_baseline_selected'}else{'network_block_selected'}
$sentinel=Join-Path $work 'network-started'
$fixture=Join-Path $work 'OpenemsFixture.exe'
[IO.File]::WriteAllText($fixture,'inert fixture bytes; never execute')
function Start-FixtureLaunchTrace($ProfilePath,$WorkDirectory) {
    $script:traceCalls+=@('start')
    if($ProfilePath -ne $launchTraceProfile -or $WorkDirectory -ne $work){throw 'Unexpected trace boundary.'}
    if($Case -eq 'trace_unavailable'){return @{status='unavailable';owned=$false}}
    return @{status='recording';owned=$true}
}
function Stop-FixtureLaunchTrace($State,$Receipt) {
    $script:traceCalls+=@('stop')
    if(-not $State.owned -or $Receipt.process_id -ne 77){throw 'Unexpected trace ownership or PID.'}
    if($Case -eq 'trace_stop_failure'){return @{status='stop_failed';event_count=0}}
    if($Case -eq 'trace_cleanup_unconfirmed'){return @{status='stop_failed';cleanup_error='stop_cleanup_unconfirmed'}}
    return @{status='captured';event_count=3}
}
function Get-Sha256 {param($Path) return ('ab'*32)}
function Start-FixtureProcess {
    param($Path,$Sentinel,$Url)
    $script:starts++
    if($Case -eq 'native_refusal') { throw [ComponentModel.Win32Exception]::new(577) }
    if($Case -ne 'timeout_before_main') {
        [IO.File]::WriteAllText($Sentinel,'started')
        $phase=if($Case -eq 'bad_phase') {'untrusted-value'} elseif($Case -eq 'oversized_phase') {'x'*65} else {'before_network'}
        [IO.File]::WriteAllText(($Sentinel+'.phase'),$phase)
    }
    $process=[pscustomobject]@{Id=77;ExitCode=$(if($Case -eq 'network_error'){31}else{0});HasExited=$false}
    $process|Add-Member ScriptMethod WaitForExit {
        param($Milliseconds)
        $script:waits+=@($Milliseconds)
        $this.HasExited=$Case -notin @(
            'timeout','timeout_before_main','kill_failure','kill_unconfirmed','trace_timeout','trace_stop_failure','timeout_export_failure')
        return $this.HasExited
    }
    $process|Add-Member ScriptMethod Kill {
        $script:killed=$true
        if($Case -eq 'kill_failure'){throw [IO.IOException]::new('owned cleanup failed')}
        $this.HasExited=$Case -ne 'kill_unconfirmed'
    }
    $process|Add-Member ScriptMethod Dispose {$script:disposed=$true}
    return $process
}
if($Case -eq 'export_failure') { function Write-Json {param($Path,$Value) throw [IO.IOException]::new('export failed')} }
if($Case -eq 'timeout_export_failure') {
    $script:writes=0
    function Write-Json {
        param($Path,$Value)
        $script:writes++
        if($script:writes -gt 1){throw [IO.IOException]::new('final checkpoint failed')}
    }
}
if($Case -eq 'overflow') { $script:result.fixture_probes=@(1..32 | ForEach-Object {@{sequence=$_}}) }
$observed=$null;$errorCategory=$null;$errorMessage=$null
try {$observed=Invoke-Fixture $fixture $sentinel 'https://example.org/' -ProbePhase $probePhase}
catch {$errorCategory=$_.Exception.GetBaseException().GetType().Name;$errorMessage=$_.Exception.Message}
@{boundary_ready=$true;observed=$observed;error_category=$errorCategory;error_message=$errorMessage;receipts=@($script:result.fixture_probes);waits=$script:waits;killed=$script:killed;disposed=$script:disposed;starts=$script:starts;cleanup_errors=$script:result.cleanup_errors;trace_calls=$script:traceCalls}|ConvertTo-Json -Depth 8 -Compress
"""


@pytest.mark.parametrize("case", ["success", "network_error", "native_refusal", "timeout", "timeout_before_main", "kill_failure", "bad_phase", "oversized_phase", "export_failure", "overflow"])
def test_owned_probe_observations_preserve_identity_deadlines_and_failures(tmp_path, case):
    result = _run_functions(tmp_path, PROBE_OBSERVATION_DRIVER, case)
    assert result["boundary_ready"] is True, "mockable process-start boundary required before host test invocation"
    if case == "overflow":
        assert result["starts"] == 0 and result["error_category"]
        assert len(result["receipts"]) == 32
        return
    assert result["starts"] == (0 if case == "export_failure" else 1)
    assert len(result["receipts"]) == 1
    receipt = result["receipts"][0]
    assert receipt["phase"] == "network_block_selected"
    assert receipt["fixture_basename"] == "OpenemsFixture.exe"
    assert receipt["sha256"] == "ab" * 32
    assert "url" not in receipt and "arguments" not in receipt and "stdout" not in receipt
    assert receipt["requested_utc"]
    if case not in {"export_failure", "native_refusal"}:
        assert result["waits"] == [15000]
        assert result["disposed"] is True
        assert receipt["start_returned_utc"] and receipt["finished_utc"]
        assert receipt["elapsed_ms"] >= 0
    if case in {"success", "network_error"}:
        assert result["error_category"] is None
        assert result["observed"]["exit"] == (31 if case == "network_error" else 0)
        assert receipt["started"] is True and receipt["managed_phase"] == "before_network"
    elif case == "native_refusal":
        assert result["observed"]["native_error"] == 577
        assert receipt["native_error"] == 577 and receipt["started"] is False
    else:
        assert result["error_category"]
    if case in {"timeout", "timeout_before_main", "kill_failure"}:
        assert receipt["timed_out"] is True and result["killed"] is True
    if case == "timeout_before_main":
        assert receipt["started"] is False and receipt["managed_phase"] == "unobserved"
    if case == "kill_failure":
        assert receipt["cleanup_error"] and result["cleanup_errors"]
    if case in {"bad_phase", "oversized_phase"}:
        assert receipt["observation_error"]


def test_owned_fixture_phase_markers_preserve_the_existing_request_contract():
    source = (ROOT / "deploy/test-controls-sandbox.ps1").read_text(encoding="utf-8-sig")
    fixture = source.split("function New-Fixture", 1)[1].split("function Start-FixtureProcess", 1)[0]
    assert 'File.WriteAllText(args[0] + ".phase", "entry")' in fixture
    assert fixture.index('"before_network"') < fixture.index("request.GetResponse()") < fixture.index('"after_response"')
    assert "request.Timeout = 8000" in fixture
    assert "SecurityProtocolType.Tls12" in fixture
    for phase in ("network_baseline_selected", "network_baseline_control", "network_block_selected", "network_block_control", "network_release_selected"):
        assert f"-ProbePhase '{phase}'" in source


@pytest.mark.parametrize(
    "case,entered,confirmed",
    [
        ("success", {"process_start", "wait_for_exit", "marker_read", "dispose"}, True),
        ("timeout_before_main", {"process_start", "wait_for_exit", "kill", "marker_read", "dispose"}, True),
        ("kill_failure", {"process_start", "wait_for_exit", "kill", "marker_read", "dispose"}, False),
        ("kill_unconfirmed", {"process_start", "wait_for_exit", "kill", "marker_read", "dispose"}, False),
        ("native_refusal", {"process_start", "marker_read"}, None),
        ("export_failure", {"marker_read"}, None),
    ],
)
def test_fixture_launch_times_distinguish_wait_cleanup_and_early_failures(tmp_path, case, entered, confirmed):
    result = _run_functions(tmp_path, PROBE_OBSERVATION_DRIVER, case)
    assert result["boundary_ready"] is True
    receipt, = result["receipts"]
    stages = receipt["stage_timings_ms"]
    assert set(stages) == {"process_start", "wait_for_exit", "kill", "marker_read", "dispose"}
    assert {name for name, duration in stages.items() if duration is not None} == entered
    assert all(0 <= stages[name] <= receipt["elapsed_ms"] for name in entered)
    assert receipt["exit_confirmed"] is confirmed
    assert result["waits"] == ([15000] if "wait_for_exit" in entered else [])
    if case in {"kill_failure", "kill_unconfirmed"}:
        assert result["cleanup_errors"]
    if case in {"timeout_before_main", "kill_unconfirmed"}:
        assert receipt["timed_out"] is True and receipt["exit"] is None


@pytest.mark.parametrize(
    "case,status,calls",
    [
        ("trace_success", "captured", ["start", "stop"]),
        ("trace_timeout", "captured", ["start", "stop"]),
        ("trace_stop_failure", "stop_failed", ["start", "stop"]),
        ("trace_unavailable", "unavailable", ["start"]),
        ("trace_baseline", None, []),
        ("trace_no_profile", None, []),
        ("trace_usb", None, []),
    ],
)
def test_fixture_launch_trace_belongs_only_to_selected_applications_probe(tmp_path, case, status, calls):
    result = _run_functions(tmp_path, PROBE_OBSERVATION_DRIVER, case)
    assert result["boundary_ready"] is True
    receipt, = result["receipts"]
    assert result["trace_calls"] == calls
    trace = receipt.get("launch_trace")
    if status:
        assert trace["status"] == status
    else:
        assert trace is None
    if case in {"trace_timeout", "trace_stop_failure"}:
        assert receipt["timed_out"] is True
        assert result["error_message"] == "Fixture process timed out."
    else:
        assert result["observed"]["exit"] == 0


def test_fixture_timeout_survives_a_secondary_checkpoint_error(tmp_path):
    result = _run_functions(tmp_path, PROBE_OBSERVATION_DRIVER, "timeout_export_failure")
    assert result["boundary_ready"] is True and result["receipts"][0]["timed_out"]
    assert result["cleanup_errors"]
    assert result["error_message"] == "Fixture process timed out."


def test_unconfirmed_trace_cleanup_aborts_the_next_probe(tmp_path):
    result = _run_functions(tmp_path, PROBE_OBSERVATION_DRIVER, "trace_cleanup_unconfirmed")
    assert result["boundary_ready"] is True and result["trace_calls"] == ["start", "stop"]
    assert result["receipts"][0]["launch_trace"]["cleanup_error"] == "stop_cleanup_unconfirmed"
    assert result["cleanup_errors"]
    assert result["observed"] is None
    assert result["error_message"]


@pytest.mark.parametrize(
    "case,terminated,kill_calls",
    [("already_exited", True, 0), ("exits_after_kill", True, 1), ("still_running", False, 1), ("kill_error", False, 1)],
)
def test_tracer_transport_checks_termination_of_its_owned_process(tmp_path, case, terminated, kill_calls):
    result = _run_functions(tmp_path, r"""
$script:killCalls=0
$process=[pscustomobject]@{HasExited=($Case -ceq 'already_exited')}
$process|Add-Member ScriptMethod Kill {
    $script:killCalls++
    if($Case -ceq 'kill_error'){throw [IO.IOException]::new('simulated kill failure')}
}
$process|Add-Member ScriptMethod WaitForExit {
    param($Milliseconds)
    if($Milliseconds -ne 1000){throw 'Unexpected transport termination bound.'}
    return ($Case -ceq 'exits_after_kill')
}
if(-not (Get-Command Confirm-FixtureTraceToolExit -CommandType Function -ErrorAction SilentlyContinue)) {
    @{terminated=$null;kill_calls=$script:killCalls}|ConvertTo-Json -Compress
    return
}
$terminated=Confirm-FixtureTraceToolExit $process
@{terminated=$terminated;kill_calls=$script:killCalls}|ConvertTo-Json -Compress
""", case)
    assert result == {"terminated": terminated, "kill_calls": kill_calls}


TRACE_OWNERSHIP_DRIVER = r"""
$start=@($tree.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Start-FixtureLaunchTrace'
},$true))
if($start.Count -ne 1){@{boundary_ready=$false}|ConvertTo-Json -Compress;return}
$commands=@($start[0].FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true))
$direct=@($start[0].FindAll({
    param($node)
    $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Static -and $node.Member.Value -eq 'Start'
},$true))
if($direct.Count -gt 0 -or @($commands|Where-Object {$_.GetCommandName() -in @($null,'wpr','wpr.exe','Start-Process')}).Count -gt 0 -or
   @($commands|Where-Object {$_.GetCommandName() -eq 'Invoke-FixtureTraceTool'}).Count -eq 0) {
    @{boundary_ready=$false}|ConvertTo-Json -Compress;return
}
$script:toolCalls=@()
$profile=Join-Path $work 'applications-launch-diagnostic.wprp'
[IO.File]::WriteAllText($profile,'inert profile; actual recorder is mocked')
function Invoke-FixtureTraceTool([string]$Tool,[string[]]$Arguments,[int]$TimeoutMs) {
    $script:toolCalls+=@(@{tool=$Tool;arguments=$Arguments;timeout_ms=$TimeoutMs})
    if($Arguments[0] -ceq '-status') {
        switch($Case) {
            'missing' { return @{kind='missing_tool';exit_code=$null;output=''} }
            'active' { return @{kind='exited';exit_code=0;output='WPR is recording trace.'} }
            'unknown' { return @{kind='exited';exit_code=1;output='unrecognized status'} }
            'idle' { return @{kind='exited';exit_code=-984076288;output='0xc5583000'} }
        }
    }
    if($Arguments[0] -ceq '-start'){return @{kind='exited';exit_code=0;output='recording started'}}
    throw 'Unexpected recorder operation.'
}
$state=Start-FixtureLaunchTrace $profile $work
@{boundary_ready=$true;status=$state.status;owned=$state.owned;calls=$script:toolCalls}|ConvertTo-Json -Depth 6 -Compress
"""


@pytest.mark.parametrize(
    "case,status,owned",
    [
        ("missing", "missing_recorder", False),
        ("active", "active_recording", False),
        ("unknown", "recorder_status_unknown", False),
        ("idle", "recording", True),
    ],
)
def test_fixture_trace_takes_ownership_only_after_verified_idle_status(tmp_path, case, status, owned):
    result = _run_functions(tmp_path, TRACE_OWNERSHIP_DRIVER, case)
    assert result["boundary_ready"] is True, "test requires a mocked recorder command boundary"
    assert result["status"] == status and result["owned"] is owned
    calls = result["calls"]
    assert [call["arguments"][0] for call in calls] == (["-status", "-start"] if owned else ["-status"])
    assert calls[0]["arguments"] == ["-status"]
    assert all(call["tool"] == "wpr.exe" and 0 < call["timeout_ms"] <= 30000 for call in calls)
    if owned:
        args = calls[1]["arguments"]
        assert args[1].endswith("applications-launch-diagnostic.wprp!OpenemsApplicationsLaunch.Light")
        assert "-filemode" not in args
        assert args[2] == "-instancename" and args[3]


def test_fixture_trace_profile_uses_bounded_kernel_buffers_without_stacks():
    profile_path = ROOT / "deploy/applications-launch-diagnostic.wprp"
    assert profile_path.is_file()
    root = ElementTree.parse(profile_path).getroot()
    profiles = [profile for profile in root.findall("./Profiles/Profile") if profile.get("LoggingMode") == "Memory"]
    assert len(profiles) == 1
    collector_refs = profiles[0].findall("./Collectors/SystemCollectorId")
    assert len(collector_refs) == 1
    collector = root.find(f"./Profiles/SystemCollector[@Id='{collector_refs[0].get('Value')}']")
    assert collector is not None
    buffer_size = int(collector.find("BufferSize").get("Value"))
    buffer_count = int(collector.find("Buffers").get("Value"))
    assert 0 < buffer_size * buffer_count <= 64 * 1024
    keywords = {node.get("Value") for node in root.findall("./Profiles/SystemProvider/Keywords/Keyword")}
    assert keywords == {"ProcessThread", "Loader", "CSwitch"}
    assert not root.findall(".//Stack")
    assert not root.findall(".//EventProvider")


@pytest.mark.parametrize(
    "stamp,expected",
    [
        ("2026-11-16T14:21:45.839592000-03:00", "2026-11-16T17:21:45.8395920Z"),
        ("2026-11-17T00:51:45.839592000+05:30", "2026-11-16T19:21:45.8395920Z"),
        ("2026-11-16T17:21:45.839592000Z", "2026-11-16T17:21:45.8395920Z"),
        ("2026-11-16T17:21:45.839592000", None),
    ],
)
def test_tracerpt_timestamp_preserves_the_instant_across_explicit_offsets(tmp_path, stamp, expected):
    result = _run_functions(tmp_path, r"""
$timestamp=$null
try { $timestamp=(Read-LaunchTraceUtc $Case).ToString('o') }
catch { $timestamp=$null }
@{timestamp=$timestamp}|ConvertTo-Json -Compress
""", stamp)
    assert result["timestamp"] == expected
