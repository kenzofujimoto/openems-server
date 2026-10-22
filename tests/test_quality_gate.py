"""CI must reject hidden skips and low security module coverage."""

import json

from tools.check_quality import CRITICAL, SERVICES, check


def reports(tmp_path, *, skipped=0, override=None):
    junit = tmp_path / "tests.junit.xml"
    junit.write_text(f'<testsuites><testsuite tests="10" skipped="{skipped}" errors="0" failures="0"/></testsuites>')
    coverage = tmp_path / "coverage.json"
    files = {name: {"summary": {"percent_covered": 100.0}} for name in CRITICAL | SERVICES}
    files.update(override or {})
    coverage.write_text(json.dumps({"files": files}))
    return junit, coverage


def test_zero_skips_and_covered_modules_pass(tmp_path):
    junit, coverage = reports(tmp_path)
    assert check(junit, coverage) == []


def test_skips_cannot_hide_missing_backends(tmp_path):
    junit, _ = reports(tmp_path, skipped=1)
    assert any("skipped" in failure for failure in check(junit))


def test_each_module_must_meet_its_own_threshold(tmp_path):
    junit, coverage = reports(tmp_path, override={"app/auth.py": {"summary": {"percent_covered": 94.99}}})
    assert any("app/auth.py" in failure and "95" in failure for failure in check(junit, coverage))


def test_unmeasured_critical_module_is_rejected(tmp_path):
    junit, coverage = reports(tmp_path)
    data = json.loads(coverage.read_text())
    del data["files"]["app/recording.py"]
    coverage.write_text(json.dumps(data))
    assert any("app/recording.py" in failure for failure in check(junit, coverage))


def test_component_coverage_cannot_hide_behind_total(tmp_path):
    junit, coverage = reports(tmp_path, override={"app/models.py": {"summary": {"percent_covered": 79.9}}})
    assert any("app/models.py" in failure and "80" in failure for failure in check(junit, coverage))
