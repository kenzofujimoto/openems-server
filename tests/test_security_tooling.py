"""Security tooling contract: scanners, gates and CI hardening stay in place (2026-10-27 review)."""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))


def test_expected_workflows_exist():
    assert {"ci.yml", "security.yml", "codeql.yml", "scorecard.yml"} <= {path.name for path in WORKFLOWS}


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda path: path.name)
def test_every_action_is_pinned_to_a_full_commit_sha(workflow):
    uses = re.findall(r"^\s*-?\s*uses:\s*(\S+)", workflow.read_text(encoding="utf-8"), flags=re.MULTILINE)
    assert uses, f"{workflow.name} uses no action"
    for reference in uses:
        if reference.startswith("./"):
            continue
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", reference), f"{workflow.name}: {reference} is not SHA-pinned"


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda path: path.name)
def test_workflows_default_to_read_only_tokens(workflow):
    text = workflow.read_text(encoding="utf-8")
    top = text.split("\njobs:", 1)[0]
    assert re.search(r"^permissions:\s*\n\s+contents: read\s*$", top, flags=re.MULTILINE) or \
        re.search(r"^permissions:\s*\{\}\s*$", top, flags=re.MULTILINE) or \
        re.search(r"^permissions: read-all\s*$", top, flags=re.MULTILINE), f"{workflow.name} lacks a read-only default"
    assert "pull_request_target" not in text, "untrusted PR code must never run with write tokens"
    assert "${{ github.event.pull_request.title" not in text and "${{ github.event.issue" not in text


def test_container_scanner_images_are_pinned_by_digest():
    source = (ROOT / "tools" / "security_scan.py").read_text(encoding="utf-8")
    images = ast.literal_eval(re.search(r"^IMAGES = (\{.*?^\})", source, flags=re.MULTILINE | re.DOTALL).group(1))
    for tool in ("gitleaks", "semgrep", "trivy", "osv-scanner", "hadolint", "zap", "actionlint", "zizmor", "python"):
        assert re.fullmatch(r"[\w./-]+@sha256:[0-9a-f]{64}", images[tool]), f"{tool} image is not digest-pinned"


def test_security_workflow_gates_every_scanner_family():
    text = (ROOT / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    for job in ("secrets:", "sast:", "dependencies:", "container:", "workflows:", "dast:"):
        assert f"\n  {job}" in text, f"security.yml misses the {job[:-1]} job"
    assert "tools/security_scan.py" in text
    # cargo-deny has no official image: CI uses its pinned action, local runs use the cargo binary.
    assert "EmbarkStudios/cargo-deny-action@" in text
    assert "\"cargo\", \"deny\"" in source_of_scanner() or "'cargo', 'deny'" in source_of_scanner()


def source_of_scanner() -> str:
    return (ROOT / "tools" / "security_scan.py").read_text(encoding="utf-8")


def test_dependabot_covers_every_ecosystem():
    text = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    for ecosystem, directory in (("pip", "/"), ("npm", "/web"), ("cargo", "/agent-rs"), ("docker", "/"),
                                 ("github-actions", "/")):
        assert re.search(rf'package-ecosystem: "{ecosystem}"\s*\n\s*directory: "{re.escape(directory)}"', text), ecosystem


def test_gitleaks_allowlist_is_limited_to_generated_test_vectors():
    config = tomllib.loads((ROOT / ".gitleaks.toml").read_text(encoding="utf-8"))
    assert config["extend"]["useDefault"] is True
    paths = [path for allow in config.get("allowlists", [config.get("allowlist", {})]) for path in allow.get("paths", [])]
    assert paths == [r"^contract/uninstall-vectors\.json$"], "only the generated uninstall vectors are exempt"


def test_accepted_findings_have_reasons_and_expiry():
    import json
    accepted = json.loads((ROOT / "security" / "accepted-findings.json").read_text(encoding="utf-8"))
    assert isinstance(accepted["findings"], list)
    for item in accepted["findings"]:
        assert {"tool", "id", "reason", "expires"} <= set(item)
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", item["expires"])
        assert len(item["reason"]) >= 20


def test_security_policy_documents_private_reporting():
    policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "Reportar uma vulnerabilidade" in policy and "security/advisories/new" in policy
