#!/usr/bin/env python3
"""Prepare the network locations Sandbox acceptance package, except its production MSI.

Build openems-agent.msi into the same folder with tools/build-msi-fixtures.ps1 -Production.
Run the generated locations.wsb manually after the implementation batch is complete.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sandbox_package import SANDBOX, write_harness


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, default=SANDBOX / "locations-input")
    parser.add_argument("--results", type=Path, default=SANDBOX / "results")
    args = parser.parse_args()
    output = args.output.resolve()
    write_harness(output, args.results.resolve(), "test-locations-sandbox.ps1", "RUN-LOCATIONS-TEST.cmd", "locations.wsb")
    print(f"wrote the harness, its launcher and locations.wsb for {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
