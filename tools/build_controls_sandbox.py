#!/usr/bin/env python3
"""Prepare a controls acceptance input folder; never install or launch anything."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sandbox_package import SANDBOX, write_harness


def build(kind: str, output: Path, results: Path) -> None:
    launcher = f"RUN-{kind.upper()}-TEST.cmd"
    write_harness(output, results, "test-controls-sandbox.ps1", launcher, f"{kind}.wsb")
    path = output / launcher
    text = path.read_text(encoding="ascii").replace(
        " -OutputDirectory", f" -Kind {kind.capitalize()} -OutputDirectory")
    path.write_text(text, encoding="ascii", newline="")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("usb", "applications"), required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--results", type=Path, default=SANDBOX / "results")
    args = parser.parse_args()
    output = (args.output or SANDBOX / f"{args.kind}-input").resolve()
    build(args.kind, output, args.results.resolve())
    print(f"prepared {args.kind} acceptance harness and manual Sandbox profile in {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
