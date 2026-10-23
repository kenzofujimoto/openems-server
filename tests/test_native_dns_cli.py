"""DNS filter CLI and service contracts on ephemeral loopback ports; system DNS is never changed."""

import json
import os
import socket
import struct
import subprocess
import time
from pathlib import Path
from xml.etree import ElementTree as ET

from tests.test_native_agent import run_agent


def free_port() -> int:
    # Windows can reserve a free UDP port for TCP (Hyper-V exclusion ranges); need both.
    for _ in range(32):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, socket.socket() as tcp:
            udp.bind(("127.0.0.1", 0))
            port = udp.getsockname()[1]
            try:
                tcp.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("no loopback port free for both UDP and TCP")


def dns_query(name: str, query_id: int = 0x4242) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split("."))
    return struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", 1, 1)


def test_dns_configuration_is_opt_in_and_serializes(native, tmp_path):
    config = tmp_path / "agent.json"
    result = run_agent(native, "configure", "--config-path", str(config), "--server", "http://127.0.0.1:1",
                       "--devid", "dns-test", "--dns-filter", "--dns-port", "15353", invitation=None)
    assert result.returncode == 0, result.stderr
    settings = json.loads(config.read_text())
    assert settings["dns_filter"] is True and settings["dns_port"] == 15353
    plain = tmp_path / "plain.json"
    assert run_agent(native, "configure", "--config-path", str(plain), "--server", "http://127.0.0.1:1",
                     "--devid", "dns-test", invitation=None).returncode == 0
    assert json.loads(plain.read_text())["dns_filter"] is False


def test_run_once_cannot_claim_dns_enforcement_without_resolver(native, tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_bytes(b"# original\n")
    result = run_agent(native, "run-once", "--server", "http://127.0.0.1:1", "--devid", "dns-test", "--dns-filter",
                       "--hosts-file", str(hosts), "--state-path", str(tmp_path / "state.json"), invitation=None)
    assert result.returncode != 0
    assert "continuous" in result.stderr.lower()
    assert hosts.read_bytes() == b"# original\n"


def test_continuous_run_serves_dns_on_configured_loopback_port(native, tmp_path):
    port = free_port()
    environment = {key: value for key, value in os.environ.items() if not key.startswith("OPENEMS_")}
    process = subprocess.Popen(
        [str(native), "run", "--server", "http://127.0.0.1:1", "--devid", "dns-test", "--dns-filter",
         "--dns-port", str(port), "--hosts-file", str(tmp_path / "hosts"), "--state-path", str(tmp_path / "state.json")],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
    )
    try:
        reply = None
        deadline = time.monotonic() + 15
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(0.5)
            while reply is None and time.monotonic() < deadline and process.poll() is None:
                client.sendto(dns_query("use-application-dns.net"), ("127.0.0.1", port))
                try:
                    reply = client.recv(512)
                # Before the agent listens, Windows reports the ICMP port unreachable as a reset.
                except (TimeoutError, ConnectionResetError):
                    time.sleep(0.2)
                    continue
        assert reply is not None, process.stderr.read1().decode(errors="replace") if process.poll() is not None else "no reply"
        assert reply[:2] == b"\x42\x42" and reply[2] & 0x80
        assert reply[3] & 0x0F == 3, "Firefox canary must be NXDOMAIN"
    finally:
        process.terminate()
        process.wait(timeout=15)


def test_installer_accepts_dns_option_only_for_setup(native, tmp_path):
    help_text = run_agent(native, "installer-prepare", "--help", invitation=None)
    assert help_text.returncode == 0 and "--dns-filter" in help_text.stdout
    result = run_agent(native, "installer-prepare", "--remove", "--dns-filter", "--config", str(tmp_path / "agent.json"), invitation=None)
    assert result.returncode != 0 and "cannot be used with" in result.stderr
    assert list(tmp_path.iterdir()) == []


def test_msi_dns_property_is_opt_in_and_validated():
    root = ET.parse(Path(__file__).resolve().parents[1] / "agent-rs/installer/openems-agent.wxs").getroot()
    ns = {"w": "http://wixtoolset.org/schemas/v4/wxs"}
    prop = root.find(".//w:Property[@Id='DNSFILTER']", ns)
    assert prop is not None and prop.attrib["Secure"] == "yes" and prop.attrib.get("Value") != "1"
    assert any("DNSFILTER" in launch.attrib["Condition"] and '"1"' in launch.attrib["Condition"]
               for launch in root.findall(".//w:Launch", ns))
    setter = root.find(".//w:SetProperty[@Id='DnsFilterArguments']", ns)
    assert setter is not None and setter.attrib["Value"] == "--dns-filter" and "DNSFILTER" in setter.attrib["Condition"]
    setup = root.find(".//w:CustomAction[@Id='PrepareAgentSetup']", ns)
    assert "[DnsFilterArguments]" in setup.attrib["ExeCommand"]
