"""Agent editions (docs/agent-editions.md): OpenEMS by default, RSM Brasil as a build option.

The Python reference agent and the native agent must show the same identity for each edition, and the
RSM edition keeps its wording byte-for-byte. These checks read the sources, so they need no build.
"""

from __future__ import annotations

import base64
import re
from pathlib import Path

import pytest

import blockpage
import brand

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "agent-rs"
BRAND_RS = (NATIVE / "src" / "brand.rs").read_text(encoding="utf-8")
WXS = (NATIVE / "installer" / "openems-agent.wxs").read_text(encoding="utf-8")


def native_brand(edition: str) -> dict[str, str]:
    """String fields of brand::OPENEMS / brand::RSM."""
    block = re.search(rf"pub const {edition.upper()}: Brand = Brand \{{(.*?)\n\}};", BRAND_RS, re.S).group(1)
    return dict(re.findall(r'(\w+): "([^"]*)"', block))


def native_page(edition: str, host: str) -> str:
    """The native template as the Python agent renders it: no category line, which only the native agent fills."""
    template = (NATIVE / "src" / f"blockpage-{edition}.html").read_text(encoding="utf-8")
    lines = [line for line in template.splitlines(keepends=True)
             if line.strip() != "{category}" and not line.lstrip().startswith(".category")]
    logo = base64.b64encode((NATIVE / "assets" / "rsm-logo.png").read_bytes()).decode()
    return "".join(lines).replace("{logo}", logo).replace("{host}", host)


@pytest.mark.parametrize("edition", brand.EDITIONS)
def test_python_and_native_block_pages_match_for_each_edition(edition):
    assert blockpage.render("blocked.example", edition).decode("utf-8") == native_page(edition, "blocked.example")


def test_editions_have_the_same_ids_in_both_agents():
    assert [native_brand(edition)["id"] for edition in brand.EDITIONS] == list(brand.EDITIONS)
    cargo = (NATIVE / "Cargo.toml").read_text(encoding="utf-8")
    assert re.search(r"^\[features\]\n(?:#.*\n)*rsm = \[\]$", cargo, re.M), "the RSM edition is the `rsm` feature"
    features = cargo.split("[features]", 1)[1].split("\n[", 1)[0]
    assert not re.search(r"^default\s*=", features, re.M), "OpenEMS stays the default build"


def test_the_rsm_edition_keeps_its_wording():
    rsm = native_brand("rsm")
    assert rsm["product"] == "RSM Endpoint"
    assert rsm["service_description"] == (
        "Applies RSM endpoint policies and reports their status to the management server.")
    page = blockpage.render("example.com", "rsm").decode("utf-8")
    assert 'alt="RSM"' in page and "RSM Brasil &middot; <strong>O poder de ser compreendido</strong>" in page


def test_the_openems_edition_is_free_of_rsm_identity():
    openems = native_brand("openems")
    assert openems["product"] == "OpenEMS Endpoint"
    assert "RSM" not in openems["service_description"]
    assert "RSM" not in (NATIVE / "src" / "blockpage-openems.html").read_text(encoding="utf-8")
    sources = [NATIVE / "src" / "session.rs", NATIVE / "src" / "service.rs", NATIVE / "src" / "bin" / "openems-session.rs"]
    for source in sources:
        assert "RSM" not in source.read_text(encoding="utf-8"), f"{source.name} hard-codes RSM; use crate::brand"


@pytest.mark.parametrize("edition", brand.EDITIONS)
def test_the_msi_metadata_follows_the_edition(edition):
    manufacturer = {"openems": "OpenEMS", "rsm": "RSM Brasil"}[edition]
    description = native_brand(edition)["service_description"]
    branch = re.search(rf'\$\(var\.Edition\) = "{edition}" \?>\n(.*?)\n<\?(?:elseif|else)', WXS, re.S).group(1)
    assert f'<?define Manufacturer = "{manufacturer}" ?>' in branch
    assert f'<?define ServiceDescription = "{description}" ?>' in branch
    assert '<?define Edition = "openems" ?>' in WXS, "the MSI defaults to OpenEMS"
    assert 'Manufacturer="$(var.Manufacturer)"' in WXS and 'Description="$(var.ServiceDescription)"' in WXS


def test_the_msi_builder_refuses_binaries_of_the_other_edition():
    builder = (ROOT / "tools" / "build-msi-fixtures.ps1").read_text(encoding="utf-8")
    assert "[ValidateSet('openems', 'rsm')][string]$Edition = 'openems'" in builder
    assert "--version" in builder and "('Edition=' + $Edition)" in builder


def test_the_python_service_installer_records_the_edition():
    installer = (ROOT / "agent" / "install_service.ps1").read_text(encoding="utf-8")
    assert "[ValidateSet('openems', 'rsm')][string]$Edition = 'openems'" in installer
    assert '"OPENEMS_AGENT_EDITION=$Edition"' in installer and "'brand.py'" in installer
