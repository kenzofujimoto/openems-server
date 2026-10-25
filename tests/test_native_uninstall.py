"""Native agent and uninstall codes (part 5b): secret delivery, release and the offline generator.

The agent runs as the current user against a disposable server, so uninstall.json stays readable by the
test; under the service it is SYSTEM-only. Removal itself needs SYSTEM and runs in the Sandbox acceptance.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import httpx

from agent.uninstall import derive_secret, release_token
from tests.test_agent_integration import live_server
from tests.test_native_agent import INVITATION
from tests.test_native_categories import stop, wait_for

ROOT = Path(__file__).resolve().parent.parent
MASTER = b"test-only-master-key-0123456789abcdef"
DEVID = "uninstall-pc"


def start(native: Path, origin: str, tmp_path: Path) -> subprocess.Popen:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("OPENEMS_")}
    environment["OPENEMS_INVITATION"] = INVITATION
    (tmp_path / "hosts").write_text("127.0.0.1 localhost\n", encoding="utf-8")
    return subprocess.Popen(
        [str(native), "run", "--server", origin, "--devid", DEVID, "--interval", "1",
         "--hosts-file", str(tmp_path / "hosts"), "--state-path", str(tmp_path / "state.json")],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=environment,
    )


def read(path: Path) -> str:
    """File contents, or "" while missing or being replaced (Windows denies reads during the rename)."""
    try:
        return path.read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError):
        return ""


def stored(tmp_path: Path) -> dict:
    try:
        return json.loads(read(tmp_path / "uninstall.json"))
    except ValueError:
        return {}


def test_the_agent_stores_its_secret_and_confirms_delivery(native, tmp_path):
    with live_server(uninstall_master_key=MASTER) as (service, origin, _):
        agent = start(native, origin, tmp_path)
        try:
            if not wait_for(lambda: stored(tmp_path).get("acked") is True, 30):
                raise AssertionError(f"secret not confirmed: {stored(tmp_path)}\n" + stop(agent))
            client_id = service.get_endpoint(DEVID).client_id
            state = stored(tmp_path)
            assert (state["client_id"], state["secret"]) == (client_id, derive_secret(MASTER, client_id).hex())
            assert (state["last_used"], state["failures"], state["release"]) == (0, 0, None)
            token = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))["device_token"]
            again = httpx.post(f"{origin}/fct/api/public/v1/uninstall_secret/", json={"client_id": client_id},
                               headers={"Authorization": f"Bearer {token}"}, trust_env=False)
            assert again.status_code == 409, "after the agent's confirmation the server keeps the secret to itself"
        finally:
            if agent.poll() is None:
                stop(agent)


def test_a_release_is_kept_while_published_and_dropped_when_revoked(native, tmp_path):
    with live_server(uninstall_master_key=MASTER) as (service, origin, client):
        agent = start(native, origin, tmp_path)
        try:
            assert wait_for(lambda: stored(tmp_path).get("acked") is True, 30), stop(agent)
            expected = release_token(derive_secret(MASTER, service.get_endpoint(DEVID).client_id))
            assert client.post("/api/v1/uninstall_release", json={"scope": "*", "released": True}).status_code == 200
            if not wait_for(lambda: stored(tmp_path).get("release") == expected, 20):
                raise AssertionError(f"release not stored: {stored(tmp_path)}\n" + stop(agent))
            assert client.post("/api/v1/uninstall_release", json={"scope": "*", "released": False}).status_code == 200
            if not wait_for(lambda: stored(tmp_path).get("release", "missing") is None, 20):
                raise AssertionError(f"revoked release kept: {stored(tmp_path)}\n" + stop(agent))
        finally:
            if agent.poll() is None:
                stop(agent)


def test_without_uninstall_codes_on_the_server_the_agent_keeps_enforcing(native, tmp_path):
    with live_server() as (_, origin, client):
        assert client.post("/api/v1/profiles/Default", json={"web_filter": {"blocked": ["example.com"]}}).status_code == 200
        agent = start(native, origin, tmp_path)
        try:
            if not wait_for(lambda: "example.com" in read(tmp_path / "hosts"), 30):
                raise AssertionError(stop(agent))
            assert not (tmp_path / "uninstall.json").exists()
            assert agent.poll() is None
        finally:
            if agent.poll() is None:
                stop(agent)


def generate(command: list[str], key: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, input=key, capture_output=True, text=True, timeout=60, check=False)


def test_the_agent_generates_the_same_offline_codes_as_the_python_tool(native):
    arguments = ["--master-key-file", "-", "--client-id", "client-1", "--counter", "19", "--count", "3"]
    key = MASTER.decode() + "\n"
    python = generate([sys.executable, str(ROOT / "tools" / "uninstall_code.py"), *arguments], key)
    agent = generate([str(native), "uninstall-code", *arguments], key)
    assert python.returncode == 0 and agent.returncode == 0, agent.stderr
    assert agent.stdout == python.stdout
    default = ["--master-key-file", "-", "--client-id", "client-1"]
    single = generate([str(native), "uninstall-code", *default], key)
    reference = generate([sys.executable, str(ROOT / "tools" / "uninstall_code.py"), *default], key)
    assert single.stdout == reference.stdout and single.stdout.count("\n") == 1


def test_the_agent_generator_never_takes_or_echoes_the_key_on_the_command_line(native, tmp_path):
    rejected = generate([str(native), "uninstall-code", "--master-key", MASTER.decode(), "--client-id", "x"], "")
    assert rejected.returncode != 0 and MASTER.decode() not in rejected.stdout + rejected.stderr
    short = tmp_path / "short.key"
    short.write_text("short-but-secret", encoding="utf-8")
    refused = generate([str(native), "uninstall-code", "--master-key-file", str(short), "--client-id", "x"], "")
    assert refused.returncode != 0 and "short-but-secret" not in refused.stdout + refused.stderr
    for count in ("0", "21"):
        result = generate([str(native), "uninstall-code", "--master-key-file", "-", "--client-id", "x",
                           "--count", count], MASTER.decode())
        assert result.returncode != 0, count


def run(native: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(native), *arguments], capture_output=True, text=True, timeout=60, check=False)


def test_removal_commands_take_the_uninstall_code(native, tmp_path):
    for command in (["installer-prepare", "--remove"], ["uninstall-service"], ["cleanup"]):
        help_text = run(native, *command[:1], "--help").stdout
        assert "--uninstall-code" in help_text, command
    misplaced = run(native, "installer-prepare", "--server", "https://e", "--uninstall-code", "ABCDE-FGHJK")
    assert misplaced.returncode != 0 and "--remove" in misplaced.stderr, "a code only makes sense for removal"


def test_removal_commands_refuse_to_run_without_system(native, tmp_path):
    config = tmp_path / "agent.json"
    config.write_text(json.dumps({"server": "https://ems.example.com", "devid": "PC1",
                                  "state_path": str(tmp_path / "state.json"),
                                  "hosts_path": str(tmp_path / "hosts")}), encoding="utf-8")
    for command in (["installer-prepare", "--remove"], ["cleanup"]):
        result = run(native, *command, "--config", str(config), "--uninstall-code", "ABCDE-FGHJK")
        assert result.returncode != 0 and "SYSTEM" in result.stderr, (command, result.stderr)


WXS = ROOT / "agent-rs" / "installer" / "openems-agent.wxs"
WIX_NS = {"w": "http://wixtoolset.org/schemas/v4/wxs"}


def test_msi_passes_a_hidden_uninstall_code_only_to_removal():
    import xml.etree.ElementTree as ET

    root = ET.parse(WXS).getroot()
    prop = root.find(".//w:Property[@Id='UNINSTALLCODE']", WIX_NS)
    assert prop is not None and prop.attrib.get("Secure") == "yes" and prop.attrib.get("Hidden") == "yes"
    removal = root.find(".//w:CustomAction[@Id='PrepareAgentRemoval']", WIX_NS)
    assert removal.attrib.get("HideTarget") == "yes", "the code must not reach the MSI log"
    assert '--uninstall-code "[UNINSTALLCODE]"' in removal.attrib["ExeCommand"].replace("&quot;", '"')
    setup = root.find(".//w:CustomAction[@Id='PrepareAgentSetup']", WIX_NS)
    assert "UNINSTALLCODE" not in setup.attrib["ExeCommand"]
    scheduled = root.find(".//w:InstallExecuteSequence/w:Custom[@Action='PrepareAgentRemoval']", WIX_NS)
    assert "NOT UPGRADINGPRODUCTCODE" in scheduled.attrib["Condition"], "upgrades never ask for a code"


def test_built_msi_hides_the_uninstall_code(tmp_path):
    import pytest

    wix = ROOT / ".venv" / "wix-tools" / "wix.exe"
    agent = ROOT / "agent-rs" / "target" / "release" / "openems-agent.exe"
    if os.name != "nt" or not wix.is_file() or not agent.is_file():
        pytest.skip("needs Windows, the portable WiX in .venv/wix-tools and a release agent build")
    environment = {**os.environ, "DOTNET_ROOT": str(ROOT / ".venv" / "dotnet-sdk")}
    package = tmp_path / "openems-agent.msi"
    built = subprocess.run([str(wix), "build", str(WXS), "-arch", "x64", "-d", "Version=0.5.0", "-d", f"AgentExe={agent}",
                            "-o", str(package)], capture_output=True, text=True, env=environment, timeout=300, check=False)
    assert built.returncode == 0, built.stdout + built.stderr
    query = (
        "$i = New-Object -ComObject WindowsInstaller.Installer; $d = $i.OpenDatabase($args[0], 0);"
        "function One($sql) { $v = $d.OpenView($sql); $v.Execute(); $r = $v.Fetch(); if ($r) { $r.StringData(1) } };"
        "One \"SELECT Value FROM Property WHERE Property='MsiHiddenProperties'\";"
        "One \"SELECT Type FROM CustomAction WHERE Action='PrepareAgentRemoval'\""
    )
    tables = subprocess.run(["powershell", "-NoProfile", "-Command", f"& {{ {query} }} '{package}'"],
                            capture_output=True, text=True, timeout=120, check=False)
    hidden, action_type = (tables.stdout.strip().splitlines() + ["", ""])[:2]
    assert "UNINSTALLCODE" in hidden.split(";"), tables.stdout + tables.stderr
    assert int(action_type) & 0x2000, "msidbCustomActionTypeHideTarget"
