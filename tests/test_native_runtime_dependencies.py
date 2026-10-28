"""MSI binaries must start on a clean Windows guest without a VC++ redistributable."""

from __future__ import annotations

import os
import struct
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def imported_dlls(path: Path) -> set[str]:
    """Read the PE import directory rather than searching arbitrary embedded strings."""
    data = path.read_bytes()
    assert data[:2] == b"MZ", f"not a Windows executable: {path.name}"
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe:pe + 4] == b"PE\0\0"
    sections = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    assert struct.unpack_from("<H", data, optional)[0] == 0x20B, "expected PE32+"
    import_rva, import_size = struct.unpack_from("<II", data, optional + 120)
    assert import_rva and import_size, "expected the native executable's import directory"
    section_table = optional + optional_size

    def offset(rva: int) -> int:
        for index in range(sections):
            size, address, raw_size, raw_offset = struct.unpack_from("<IIII", data, section_table + index * 40 + 8)
            if address <= rva < address + max(size, raw_size):
                result = raw_offset + rva - address
                assert result < len(data), "PE RVA exceeds file"
                return result
        raise AssertionError(f"unmapped PE RVA: {rva:#x}")

    names = set()
    directory = offset(import_rva)
    for index in range(import_size // 20):
        descriptor = struct.unpack_from("<IIIII", data, directory + index * 20)
        if not any(descriptor):
            return names
        name = offset(descriptor[3])
        names.add(data[name:data.index(b"\0", name)].decode("ascii").lower())
    raise AssertionError("unterminated PE import directory")


def test_repository_root_cargo_builds_discover_the_static_runtime_configuration():
    # Cargo resolves configuration from cwd ancestors, not --manifest-path's directory.
    config = ROOT / ".cargo/config.toml"
    assert config.is_file(), "root cargo --manifest-path builds must discover static CRT settings"
    settings = tomllib.loads(config.read_text(encoding="utf-8"))
    assert settings["target"]["x86_64-pc-windows-msvc"]["rustflags"] == ["-C", "target-feature=+crt-static"]


@pytest.mark.windows_only
@pytest.mark.skipif(os.name != "nt", reason="Windows PE import contract")
@pytest.mark.parametrize("name", ["openems-agent.exe", "openems-session.exe", "openems-platform.exe"])
def test_native_binaries_do_not_require_a_visual_cpp_redistributable(native, name):
    imports = imported_dlls(native.with_name(name))
    redistributables = {dll for dll in imports if dll.startswith(("vcruntime", "msvcp", "concrt"))}
    assert not redistributables, f"{name} requires unshipped redistributables: {sorted(redistributables)}"
