"""Shared pieces of the Windows Sandbox acceptance packages: the harness copy, its launcher and the profile.

The profile maps the package read-only to C:\\openems-input and the results folder to C:\\openems-results,
with clipboard disabled and no LogonCommand: the operator starts the run with Win+R.
"""

from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SANDBOX = ROOT / ".venv" / "sandbox-acceptance"


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


def write_harness(output: Path, results: Path, harness: str, launcher: str, profile_name: str) -> None:
    """Copy deploy/<harness>, write <launcher> that runs it and <profile_name> next to the output folder."""
    output.mkdir(parents=True, exist_ok=True)
    results.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "deploy" / harness, output / harness)
    (output / launcher).write_text(
        "@echo off\r\npowershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -File "
        f"C:\\openems-input\\{harness} -OutputDirectory C:\\openems-results\r\n", encoding="ascii", newline="")
    for leftover in output.glob("*.wixpdb"):
        leftover.unlink()
    (output.parent / profile_name).write_text(profile(output, results), encoding="utf-8")
