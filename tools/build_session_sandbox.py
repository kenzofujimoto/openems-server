#!/usr/bin/env python3
"""Prepare the session component Sandbox package (deploy/test-session-sandbox.ps1), except the MSIs.

Writes the harness, RUN-SESSION-TEST.cmd and the session.wsb profile next to the output folder. Build the
MSIs into the same folder with tools/build-msi-fixtures.ps1 -Production (and -Production -Next).

    python tools/build_session_sandbox.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sandbox_package import SANDBOX, write_harness


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, default=SANDBOX / "session-input")
    parser.add_argument("--results", type=Path, default=SANDBOX / "results")
    args = parser.parse_args()
    output = args.output.resolve()
    write_harness(output, args.results.resolve(), "test-session-sandbox.ps1", "RUN-SESSION-TEST.cmd", "session.wsb")
    print(f"wrote the harness, its launcher and session.wsb for {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
