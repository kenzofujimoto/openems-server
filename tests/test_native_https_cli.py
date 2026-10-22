"""HTTPS lifecycle CLI contracts, without changing Windows trust or system hosts."""

import json
from pathlib import Path
from xml.etree import ElementTree as ET

from tests.test_native_agent import run_agent


def test_trust_commands_are_explicit(native):
    help_text = run_agent(native, "--help", invitation=None)
    assert help_text.returncode == 0
    assert "install-block-page-trust" in help_text.stdout
    assert "remove-block-page-trust" in help_text.stdout


def test_missing_configuration_does_not_create_authority(native, tmp_path):
    config = tmp_path / "missing.json"
    result = run_agent(native, "install-block-page-trust", "--config", str(config), invitation=None)
    assert result.returncode != 0
    assert list(tmp_path.iterdir()) == []


def test_run_once_cannot_claim_https_enforcement_without_listener(native, tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_bytes(b"# original\n")
    result = run_agent(native, "run-once", "--server", "http://127.0.0.1:1", "--devid", "tls-test", "--block-page", "--block-page-https", "--hosts-file", str(hosts), "--state-path", str(tmp_path / "state.json"), invitation=None)
    assert result.returncode != 0
    assert "continuous" in result.stderr.lower()
    assert hosts.read_bytes() == b"# original\n"


def test_https_configuration_is_opt_in_and_serializes(native, tmp_path):
    config = tmp_path / "agent.json"
    result = run_agent(native, "configure", "--config-path", str(config), "--server", "http://127.0.0.1:1", "--devid", "tls-test", "--block-page", "--block-page-https", "--block-page-port", "18080", "--block-page-https-port", "18443", invitation=None)
    assert result.returncode == 0, result.stderr
    settings = json.loads(config.read_text())
    assert settings["block_page_https"] is True
    assert settings["block_page_https_port"] == 18443
    assert not (tmp_path / "https").exists()


def test_msi_removes_owned_root_before_deleting_executable():
    root = ET.parse(Path(__file__).resolve().parents[1] / "agent-rs/installer/openems-agent.wxs").getroot()
    ns = {"w": "http://wixtoolset.org/schemas/v4/wxs"}
    action = root.find(".//w:CustomAction[@Id='PrepareAgentRemoval']", ns)
    assert action is not None, "MSI must not leave its trusted root after removal"
    assert action.attrib["ExeCommand"] == "installer-prepare --remove"
    assert action.attrib["BinaryRef"] == "AgentActions"
    assert action.attrib["Return"] == "check"
    sequence = root.find(".//w:InstallExecuteSequence/w:Custom[@Action='PrepareAgentRemoval']", ns)
    assert sequence is not None and sequence.attrib["After"] == "StopServices"
    assert 'NOT UPGRADINGPRODUCTCODE' in sequence.attrib["Condition"]


def test_installer_cli_exposes_explicit_transaction_commands(native):
    result = run_agent(native, "installer-prepare", "--help", invitation=None)
    assert result.returncode == 0, result.stderr
    assert "--block-page-https" in result.stdout
    assert "--remove" in result.stdout
    for command in ("installer-rollback", "installer-commit"):
        result = run_agent(native, command, "--help", invitation=None)
        assert result.returncode == 0, result.stderr


def test_installer_cli_rejects_removal_with_enable_options(native, tmp_path):
    path = tmp_path / "agent.json"
    result = run_agent(native, "installer-prepare", "--remove", "--block-page", "--config", str(path), invitation=None)
    assert result.returncode != 0
    assert "cannot be used with" in result.stderr
    assert list(tmp_path.iterdir()) == []


def test_msi_opt_in_and_transaction_sequence():
    root = ET.parse(Path(__file__).resolve().parents[1] / "agent-rs/installer/openems-agent.wxs").getroot()
    ns = {"w": "http://wixtoolset.org/schemas/v4/wxs"}
    for name in ("BLOCKPAGE", "BLOCKPAGEHTTPS"):
        prop = root.find(f".//w:Property[@Id='{name}']", ns)
        assert prop is not None and prop.attrib["Secure"] == "yes"
        assert prop.attrib.get("Value") != "1"
        assert any(name in launch.attrib["Condition"] and '"1"' in launch.attrib["Condition"] for launch in root.findall(".//w:Launch", ns))
    assert root.find(".//w:MajorUpgrade", ns).attrib["Schedule"] == "afterInstallInitialize"
    assert root.find(".//w:Binary[@Id='AgentActions']", ns) is not None
    for suffix in ("Setup", "Removal"):
        prepare = root.find(f".//w:CustomAction[@Id='PrepareAgent{suffix}']", ns)
        rollback = root.find(f".//w:CustomAction[@Id='RollbackAgent{suffix}']", ns)
        commit = root.find(f".//w:CustomAction[@Id='CommitAgent{suffix}']", ns)
        assert prepare is not None and rollback is not None and commit is not None
        assert rollback.attrib["Execute"] == "rollback"
        assert commit.attrib["Execute"] == "commit"
        for action in (prepare, rollback, commit):
            assert action.attrib["BinaryRef"] == "AgentActions"
            assert action.attrib["Impersonate"] == "no" and action.attrib["Return"] == "check"
        scheduled = root.find(f".//w:Custom[@Action='RollbackAgent{suffix}']", ns)
        assert scheduled.attrib["Before"] == f"PrepareAgent{suffix}"
    setup = root.find(".//w:CustomAction[@Id='PrepareAgentSetup']", ns)
    assert "installer-prepare" in setup.attrib["ExeCommand"]
    assert "[BlockPageArguments]" in setup.attrib["ExeCommand"]
    assert "[HttpsBlockPageArguments]" in setup.attrib["ExeCommand"]
