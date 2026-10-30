"""Exercise only pure JSON functions; never invoke the acceptance harness on the host."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest

from agent.policy import policy_digest

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
pytestmark = [pytest.mark.windows_only, pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell 5.1")]


@pytest.mark.parametrize("selector", [
    pytest.param(None, id="baseline-release"),
    pytest.param("SERIAL123", id="ordinary-selector"),
    pytest.param(r"USBSTOR\Disk&Ven_Generic&Prod_Test\SYNTHETIC&0", id="physical-instance-ampersands"),
    pytest.param("<device>'publisher'>&", id="html-characters"),
    pytest.param('path\\with\\"quoted"\\selector', id="quotes-and-backslashes"),
    pytest.param(r"literal\u0026\u003c\u003e\u0027", id="literal-unicode-escape-text"),
    pytest.param("ação-日本語-🚀", id="unicode-and-supplementary-plane"),
    pytest.param("line\u0085separator\u2028paragraph\u2029", id="unicode-separators"),
    pytest.param("\b\f\n\r\t\x00\x1f", id="json-control-escapes"),
    pytest.param("".join(chr(value) for value in range(32)), id="every-c0-control"),
])
def test_ps51_assignment_encoding_matches_the_server_without_running_the_harness(tmp_path, selector):
    # These are encoder contracts. Selector validation remains a separate agent/server boundary.
    body = {
        "web_filter": {"blocked": []},
        "app_control": {"blocked": [], "execution_rules": [], "network_blocked": []},
        "usb_control": {"default_action": "allow", "rules": []},
    }
    if selector is not None:
        body["usb_control"]["rules"] = [{"id": "block-fixture", "action": "block", "instance_id": selector}]
    fixture = tmp_path / "body.json"
    fixture.write_text(json.dumps(body, ensure_ascii=False), encoding="utf-8")
    driver = tmp_path / "pure-json-functions.ps1"
    driver.write_text(r"""param([string]$Source, [string]$InputPath)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$tokens=$null;$errors=$null
$tree=[System.Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count) { throw 'Harness source did not parse.' }
foreach($name in @('ConvertTo-Canonical','New-Assignment')) {
    $definition=$tree.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
    if($null -eq $definition) { throw 'Required pure JSON function is missing.' }
    # Load only these two definitions. The harness top-level script is never executed.
    . ([scriptblock]::Create($definition.Extent.Text))
}
$body=Get-Content -LiteralPath $InputPath -Raw -Encoding UTF8 | ConvertFrom-Json
$assignment=New-Assignment $body 5
[ordered]@{canonical=(ConvertTo-Canonical $body);assignment=$assignment;engine=$PSVersionTable.PSVersion.Major} | ConvertTo-Json -Depth 24 -Compress
""", encoding="utf-8-sig")
    result = subprocess.run([
        str(POWERSHELL), "-NoProfile", "-File", str(driver),
        "-Source", str(ROOT / "deploy/test-controls-sandbox.ps1"), "-InputPath", str(fixture),
    ], capture_output=True, encoding="utf-8", timeout=30, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    observed = json.loads(result.stdout.lstrip("\ufeff"))
    assert observed["engine"] == 5
    assert json.loads(observed["canonical"]) == body
    assert observed["canonical"] == json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert observed["assignment"] == {"vdom": "Default", "version": 5, "digest": policy_digest(body), "body": body}
