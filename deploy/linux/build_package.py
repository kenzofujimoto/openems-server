#!/usr/bin/env python3
"""Build a DEB or native RPM from matching prebuilt Linux agent/helper ELF files; never install it."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
MACHINES = {62: ("amd64", "x86_64"), 183: ("arm64", "aarch64")}


def source(name: str) -> bytes:
    """Maintainer scripts must have LF even when built from a Windows checkout."""
    return (HERE / name).read_text(encoding="utf-8").encode("utf-8")


def binary(path: Path) -> tuple[bytes, int]:
    data = path.read_bytes()
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("agent and helper must be 64-bit little-endian Linux ELF binaries")
    kind, machine = struct.unpack_from("<HH", data, 16)
    if kind not in (2, 3) or machine not in MACHINES:
        raise ValueError("unsupported ELF architecture or executable type")
    return data, machine


def payload(agent: bytes, helper: bytes) -> dict[str, tuple[bytes | None, int]]:
    return {
        "etc/openems": (None, 0o700), "var/lib/openems": (None, 0o700),
        "usr/bin/openems-agent": (agent, 0o755),
        "usr/libexec/openems-platform": (helper, 0o755),
        "usr/lib/systemd/system/openems-agent.service": (source("openems-agent.service"), 0o644),
        "usr/share/openems/SUPPORT.md": (source("SUPPORT.md"), 0o644),
    }


def archive(files: dict[str, tuple[bytes | None, int]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, (data, mode) in sorted(files.items()):
            item = tarfile.TarInfo(name)
            item.uid = item.gid = item.mtime = 0
            item.uname = item.gname = "root"
            item.mode = mode
            if data is None:
                item.type = tarfile.DIRTYPE
                tar.addfile(item)
            else:
                item.size = len(data)
                tar.addfile(item, io.BytesIO(data))
    return gzip.compress(output.getvalue(), mtime=0)


def ar(files: dict[str, bytes]) -> bytes:
    output = bytearray(b"!<arch>\n")
    for name, data in files.items():
        header = f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n".encode("ascii")
        if len(header) != 60:
            raise ValueError("invalid archive member name")
        output.extend(header)
        output.extend(data)
        if len(data) % 2:
            output.extend(b"\n")
    return bytes(output)


def deb(version: str, machine: int, agent: bytes, helper: bytes, output: Path) -> Path:
    architecture = MACHINES[machine][0]
    control = (f"Package: openems-agent\nVersion: {version}\nArchitecture: {architecture}\n"
               "Maintainer: OpenEMS operators\nSection: admin\nPriority: optional\n"
               "Depends: libc6, systemd, iproute2\nRecommends: usbguard, fapolicyd\n"
               "Description: Native endpoint policy agent with owned Linux integration\n")
    scripts = {name: (source(name), 0o755) for name in ("postinst", "prerm", "postrm")}
    controls = {"control": (control.encode(), 0o644), **scripts}
    target = output / f"openems-agent_{version}_{architecture}.deb"
    target.write_bytes(ar({"debian-binary": b"2.0\n", "control.tar.gz": archive(controls),
                           "data.tar.gz": archive(payload(agent, helper))}))
    return target


def rpm(version: str, machine: int, agent: bytes, helper: bytes, output: Path, program: str) -> Path:
    if "~" in version or "+" in version:
        raise ValueError("RPM version must contain only letters, digits and dots")
    architecture = MACHINES[machine][1]
    with tempfile.TemporaryDirectory(prefix="openems-rpm-") as temporary:
        top = Path(temporary)
        for folder in ("BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS"):
            (top / folder).mkdir()
        staging = top / "SOURCES/root"
        for name, (data, mode) in payload(agent, helper).items():
            path = staging / name
            if data is None:
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            path.chmod(mode)
        before = (HERE / "prerm").read_text()
        after = (HERE / "postinst").read_text()
        spec = (f"Name: openems-agent\nVersion: {version}\nRelease: 1\nSummary: Native endpoint agent\n"
                f"License: MIT\nBuildArch: {architecture}\nRequires: systemd, iproute\n"
                "%description\nOpenEMS endpoint agent; configure and enroll before starting.\n"
                "%install\nmkdir -p %{buildroot}\ncp -a %{_sourcedir}/root/. %{buildroot}/\n"
                "%preun\nif [ \"$1\" -eq 0 ]; then set -- remove; else set -- upgrade; fi\n" + before +
                "\n%posttrans\n" + after + "\n%postun\n" + (HERE / "postrm").read_text() +
                "\n%files\n%attr(0700,root,root) %dir /etc/openems\n"
                "%attr(0700,root,root) %dir /var/lib/openems\n/usr/bin/openems-agent\n"
                "/usr/libexec/openems-platform\n/usr/lib/systemd/system/openems-agent.service\n/usr/share/openems/SUPPORT.md\n")
        path = top / "SPECS/openems-agent.spec"
        path.write_text(spec, encoding="utf-8")
        result = subprocess.run([program, "--define", f"_topdir {top}", "--define", "debug_package %{nil}",
                                 "--target", architecture, "-bb", str(path)], capture_output=True,
                                text=True, timeout=180, check=False)
        if result.returncode:
            raise ValueError("rpmbuild failed; check its native toolchain and target architecture")
        packages = list((top / "RPMS").rglob("*.rpm"))
        if len(packages) != 1:
            raise ValueError("rpmbuild did not produce exactly one binary package")
        target = output / packages[0].name
        shutil.copyfile(packages[0], target)
        return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--format", choices=("deb", "rpm"), default="deb")
    parser.add_argument("--version", default="0.5.0")
    args = parser.parse_args()
    try:
        if not re.fullmatch(r"[0-9][A-Za-z0-9.+~]{0,63}", args.version):
            raise ValueError("invalid package version")
        agent, machine = binary(args.agent)
        helper, helper_machine = binary(args.helper)
        if machine != helper_machine:
            raise ValueError("agent/helper ELF architecture mismatch")
        program = shutil.which("rpmbuild") if args.format == "rpm" else None
        if args.format == "rpm" and program is None:
            raise ValueError("RPM packaging requires native rpmbuild; no RPM artifact was generated")
        args.output.mkdir(parents=True, exist_ok=True)
        target = deb(args.version, machine, agent, helper, args.output) if args.format == "deb" else rpm(
            args.version, machine, agent, helper, args.output, str(program))
        manifest = {"package": target.name, "version": args.version, "architecture": MACHINES[machine][0],
                    "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                    "agent_sha256": hashlib.sha256(agent).hexdigest(), "helper_sha256": hashlib.sha256(helper).hexdigest(),
                    "acceptance": "pending disposable Linux VM; building an archive does not validate enforcement"}
        target.with_suffix(".json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(target)
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Package build refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
