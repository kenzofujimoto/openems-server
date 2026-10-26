"""Inspect real package artifacts; no installation or service mutations occur on the host."""

from __future__ import annotations

import hashlib
import io
import json
import struct
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "deploy/linux/build_package.py"


def elf(path: Path, machine: int = 62) -> Path:
    content = bytearray(64)
    content[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", content, 16, 2, machine, 1)
    path.write_bytes(content)
    return path


def ar_members(data: bytes) -> dict[str, bytes]:
    assert data.startswith(b"!<arch>\n")
    offset, result = 8, {}
    while offset < len(data):
        header = data[offset:offset + 60]
        assert header[58:] == b"`\n"
        size = int(header[48:58])
        name = header[:16].decode().strip().rstrip("/")
        result[name] = data[offset + 60:offset + 60 + size]
        offset += 60 + size + size % 2
    return result


def build(tmp_path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(BUILDER), "--agent", str(tmp_path / "agent"),
         "--helper", str(tmp_path / "helper"), "--output", str(tmp_path / "out"), *extra],
        capture_output=True, text=True, timeout=60, check=False,
    )


def test_debian_package_contains_matching_binaries_private_state_and_recovery_hooks(tmp_path):
    agent, helper = elf(tmp_path / "agent"), elf(tmp_path / "helper")
    result = build(tmp_path)
    assert result.returncode == 0, result.stderr
    package = tmp_path / "out/openems-agent_0.5.0_amd64.deb"
    members = ar_members(package.read_bytes())
    assert members["debian-binary"] == b"2.0\n"
    with tarfile.open(fileobj=io.BytesIO(members["data.tar.gz"]), mode="r:gz") as archive:
        names = set(archive.getnames())
        for name in ("usr/bin/openems-agent", "usr/libexec/openems-platform", "usr/lib/systemd/system/openems-agent.service"):
            assert name in names
        assert archive.extractfile("usr/bin/openems-agent").read() == agent.read_bytes()
        assert archive.extractfile("usr/libexec/openems-platform").read() == helper.read_bytes()
        assert archive.getmember("etc/openems").mode == 0o700
        assert archive.getmember("var/lib/openems").mode == 0o700
        unit = archive.extractfile("usr/lib/systemd/system/openems-agent.service").read().decode()
        assert "ExecStartPre=/usr/libexec/openems-platform dns-prepare" in unit
        assert "ExecStopPost=/usr/libexec/openems-platform dns-remove" in unit
        assert "Restart=always" in unit and "ConditionPathExists=/etc/openems/agent.json" in unit
    with tarfile.open(fileobj=io.BytesIO(members["control.tar.gz"]), mode="r:gz") as archive:
        control = archive.extractfile("control").read().decode()
        assert "Architecture: amd64" in control and "systemd" in control and "iproute2" in control
        before = archive.extractfile("prerm").read().decode()
        assert "policy-remove" in before and "cleanup-hosts" in before
        assert archive.getmember("prerm").mode == 0o755
    manifest = json.loads((package.with_suffix(".json")).read_text())
    assert manifest["sha256"] == hashlib.sha256(package.read_bytes()).hexdigest()
    assert manifest["agent_sha256"] == hashlib.sha256(agent.read_bytes()).hexdigest()


def test_builder_refuses_mismatched_or_non_elf_binaries_before_writing_output(tmp_path):
    elf(tmp_path / "agent")
    elf(tmp_path / "helper", machine=183)
    result = build(tmp_path)
    assert result.returncode != 0 and "architecture" in result.stderr.lower()
    assert not (tmp_path / "out").exists()
    (tmp_path / "helper").write_bytes(b"MZnot-a-linux-binary")
    result = build(tmp_path)
    assert result.returncode != 0 and "ELF" in result.stderr
    assert not (tmp_path / "out").exists()


def test_debian_shell_scripts_work_after_a_windows_crlf_checkout(tmp_path, monkeypatch):
    source = tmp_path / "sources"
    source.mkdir()
    for path in BUILDER.parent.iterdir():
        if path.is_file():
            (source / path.name).write_bytes(path.read_text(encoding="utf-8").replace("\n", "\r\n").encode())
    monkeypatch.setitem(globals(), "BUILDER", source / "build_package.py")
    elf(tmp_path / "agent")
    elf(tmp_path / "helper")
    result = build(tmp_path)
    assert result.returncode == 0, result.stderr
    members = ar_members((tmp_path / "out/openems-agent_0.5.0_amd64.deb").read_bytes())
    with tarfile.open(fileobj=io.BytesIO(members["control.tar.gz"]), mode="r:gz") as archive:
        for name in ("postinst", "prerm", "postrm"):
            data = archive.extractfile(name).read()
            assert data.startswith(b"#!/bin/sh\n") and b"\r" not in data


def test_macos_sources_require_signed_binaries_and_do_not_claim_native_extensions():
    import plistlib

    plist = plistlib.loads((ROOT / "deploy/macos/com.openems.agent.plist").read_bytes())
    assert plist["Label"] == "com.openems.agent"
    assert plist["RunAtLoad"] and plist["KeepAlive"]
    assert plist["ProgramArguments"] == ["/usr/local/libexec/openems-agent", "run", "--config", "/etc/openems/agent.json"]
    script = (ROOT / "deploy/macos/build-package.sh").read_text()
    assert '"$(uname -s)" != "Darwin"' in script
    assert "codesign --verify --strict" in script and "productsign" in script
    assert "OPENEMS_INSTALLER_IDENTITY" in script
    support = (ROOT / "deploy/macos/SUPPORT.md").read_text()
    assert "Network Extension" in support and "Endpoint Security" in support
    assert "not implemented" in support
