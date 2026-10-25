#!/usr/bin/env python3
"""Prepare the uninstall code Sandbox package (deploy/test-uninstall-sandbox.ps1), except the MSIs.

Writes the test-only master key from contract/uninstall-vectors.json, 20 codes from tools/uninstall_code.py
(the codes a panel would show), the harness and its launcher, and the uninstall.wsb profile next to the
output folder. Build the MSIs into the same folder with tools/build-msi-fixtures.ps1 -Production (and -Next).

    python tools/build_uninstall_sandbox.py
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SANDBOX = ROOT / ".venv" / "sandbox-acceptance"
CLIENT_ID = "sandbox-uninstall"
LAUNCHER = ("@echo off\r\npowershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -File "
            "C:\\openems-input\\test-uninstall-sandbox.ps1 -OutputDirectory C:\\openems-results\r\n")


def profile(output: Path, results: Path) -> str:
    return f"""<Configuration>
  <Networking>Enable</Networking>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{output}</HostFolder>
      <SandboxFolder>C:\\openems-input</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>{results}</HostFolder>
      <SandboxFolder>C:\\openems-results</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
</Configuration>
"""


def build(output: Path, results: Path) -> dict[str, str]:
    vectors = json.loads((ROOT / "contract" / "uninstall-vectors.json").read_text(encoding="utf-8"))
    key = vectors["master_key"]  # test-only fixture, never a real key
    output.mkdir(parents=True, exist_ok=True)
    results.mkdir(parents=True, exist_ok=True)
    (output / "master.key").write_text(key + "\n", encoding="utf-8", newline="\n")
    listed = subprocess.run([sys.executable, str(ROOT / "tools" / "uninstall_code.py"), "--master-key-file", "-",
                             "--client-id", CLIENT_ID, "--count", "20"],
                            input=key, capture_output=True, text=True, check=True)
    codes = dict(line.split() for line in listed.stdout.splitlines())
    (output / "codes.json").write_text(json.dumps({"client_id": CLIENT_ID, "codes": codes}, indent=2) + "\n",
                                       encoding="utf-8")
    shutil.copyfile(ROOT / "deploy" / "test-uninstall-sandbox.ps1", output / "test-uninstall-sandbox.ps1")
    (output / "RUN-UNINSTALL-TEST.cmd").write_text(LAUNCHER, encoding="ascii", newline="")
    for leftover in output.glob("*.wixpdb"):
        leftover.unlink()
    (output.parent / "uninstall.wsb").write_text(profile(output, results), encoding="utf-8")
    return codes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, default=SANDBOX / "uninstall-input")
    parser.add_argument("--results", type=Path, default=SANDBOX / "results")
    args = parser.parse_args()
    codes = build(args.output.resolve(), args.results.resolve())
    print(f"wrote {len(codes)} codes, the key, the harness and uninstall.wsb for {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
