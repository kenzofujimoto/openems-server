"""HTTPS lifecycle CLI contracts, without changing Windows trust or system hosts."""

import json

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
