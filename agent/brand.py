"""Agent edition, mirroring agent-rs/src/brand.rs and the panel's VITE_BRAND.

OpenEMS is the default. The RSM Brasil edition is chosen with
OPENEMS_AGENT_EDITION=rsm in the agent's environment (install_service.ps1
-Edition rsm stores it for the service), the Python counterpart of
`cargo build --features rsm`. Only user-visible text changes; policy never does.
"""

from __future__ import annotations

import os

EDITIONS = ("openems", "rsm")


def resolve(value: str | None) -> str:
    """Unknown or missing values fall back to OpenEMS, like the panel and the native build."""
    return "rsm" if value == "rsm" else "openems"


EDITION = resolve(os.environ.get("OPENEMS_AGENT_EDITION"))
