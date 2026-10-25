"""Location selection through the real server and native agent, using only disposable files.

No system DNS, service, trust root or installed agent is changed. The local TLS probe uses a
temporary self-signed certificate pinned by its DER digest, without installing it as trusted.
"""

from __future__ import annotations

import hashlib
import json
import os
import socketserver
import ssl
import subprocess
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tests.test_agent_integration import live_server
from tests.test_native_agent import INVITATION
from tests.test_native_categories import stop, wait_for

DEVID = "locations-pc"


def start(native: Path, origin: str, directory: Path) -> subprocess.Popen:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("OPENEMS_")}
    environment["OPENEMS_INVITATION"] = INVITATION
    return subprocess.Popen(
        [str(native), "run", "--server", origin, "--devid", DEVID, "--interval", "1",
         "--hosts-file", str(directory / "hosts"), "--state-path", str(directory / "state.json")],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=environment,
    )


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError):
        return ""


def configure(client, signals: dict) -> dict:
    client.post("/api/v1/profiles/Default", json={"web_filter": {"blocked": ["outside.example"]}}).raise_for_status()
    client.post("/api/v1/profiles/Office", json={"web_filter": {"blocked": ["inside.example"]}}).raise_for_status()
    definition = {"id": "office", "name": "Escritório", **signals}
    client.post("/api/v1/network_locations", json=definition).raise_for_status()
    client.post("/api/v1/location_policies", json={
        "vdom": "Default", "location_id": "office", "inside_vdom": "Office",
    }).raise_for_status()
    return definition


def applied(client, vdom: str, location: str) -> bool:
    response = client.get("/api/v1/endpoints/detail", params={"devid": DEVID})
    if response.status_code != 200:
        return False
    detail = response.json()
    return detail.get("applied_vdom") == vdom and detail.get("location") == location and not detail.get("last_error")


def test_native_switches_actual_policy_ack_and_notices_and_expires_public_ip_on_restart(native, tmp_path):
    (tmp_path / "hosts").write_text("# checkpoint\n", encoding="utf-8")
    with live_server() as (_, origin, client):
        definition = configure(client, {"public_cidrs": ["127.0.0.1/32"]})
        agent = start(native, origin, tmp_path)
        try:
            assert wait_for(lambda: applied(client, "Office", "office"), 20), read(tmp_path / "hosts")
            assert "inside.example" in read(tmp_path / "hosts")
            assert "outside.example" not in read(tmp_path / "hosts")
            definition["public_cidrs"] = ["192.0.2.0/24"]
            client.put("/api/v1/network_locations/office", json=definition).raise_for_status()
            assert wait_for(lambda: applied(client, "Default", ""), 20)
            assert "outside.example" in read(tmp_path / "hosts")
            assert "inside.example" not in read(tmp_path / "hosts")
            notices = json.loads(read(tmp_path / "session.json"))["notices"]
            assert any("Rede da empresa" in notice["text"] for notice in notices)
            assert any("Fora da rede da empresa" in notice["text"] for notice in notices)
            # Stop while inside: an old public address must not grant an inside policy offline.
            definition["public_cidrs"] = ["127.0.0.1/32"]
            client.put("/api/v1/network_locations/office", json=definition).raise_for_status()
            assert wait_for(lambda: applied(client, "Office", "office"), 20)
            assert wait_for(lambda: '"locations"' in read(tmp_path / "state.json"), 10)
        finally:
            stop(agent)
    offline = start(native, origin, tmp_path)
    try:
        assert wait_for(lambda: "outside.example" in read(tmp_path / "hosts"), 15)
        assert "inside.example" not in read(tmp_path / "hosts")
        saved = json.loads(read(tmp_path / "state.json"))["profile"]
        assert saved["vdom"] == "Default" and saved["locations"][0]["id"] == "office"
    finally:
        stop(offline)


@contextmanager
def pinned_probe(directory: Path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                   .not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))
    cert_path, key_path = directory / "probe.pem", directory / "probe-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            try:
                with context.wrap_socket(self.request, server_side=True) as connection:
                    connection.recv(1)
            except (OSError, ssl.SSLError):
                pass  # A certificate-only probe is allowed to close immediately after the handshake.

    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler) as server:
        server.daemon_threads = True
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            digest = hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
            yield {"host": "localhost", "port": server.server_address[1], "sha256": digest}
        finally:
            server.shutdown()
            worker.join(timeout=5)


@pytest.mark.skipif(os.name != "nt", reason="Windows adapter signals are the current native implementation")
def test_native_uses_live_local_signals_offline_and_rejects_a_changed_certificate(native, tmp_path):
    (tmp_path / "hosts").write_text("# checkpoint\n", encoding="utf-8")
    with pinned_probe(tmp_path) as probe:
        with live_server() as (_, origin, client):
            definition = configure(client, {"cidrs": ["0.0.0.0/0"], "probe": probe})
            agent = start(native, origin, tmp_path)
            try:
                assert wait_for(lambda: applied(client, "Office", "office"), 25), stop(agent)
                definition["probe"] = {**probe, "sha256": "00" * 32}
                client.put("/api/v1/network_locations/office", json=definition).raise_for_status()
                assert wait_for(lambda: applied(client, "Default", ""), 25)
                definition["probe"] = probe
                client.put("/api/v1/network_locations/office", json=definition).raise_for_status()
                assert wait_for(lambda: applied(client, "Office", "office"), 25)
            finally:
                if agent.poll() is None:
                    stop(agent)
        # Definitions and both policies survive, but each observation is collected again.
        offline = start(native, origin, tmp_path)
        try:
            assert wait_for(lambda: "inside.example" in read(tmp_path / "hosts"), 20)
            assert "outside.example" not in read(tmp_path / "hosts")
        finally:
            stop(offline)
