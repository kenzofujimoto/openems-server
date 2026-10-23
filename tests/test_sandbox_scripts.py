"""Guards shared by every Sandbox harness script."""
import re
from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parents[1] / 'deploy'
HARNESSES = sorted(DEPLOY.glob('test-*-sandbox.ps1'))


@pytest.mark.parametrize('script', HARNESSES, ids=lambda path: path.name)
def test_no_statement_lost_its_variable(script):
    # A shell-expanded "$name = ..." leaves " = ...", which parses as a command named "=".
    broken = [number for number, line in enumerate(script.read_text(encoding='utf-8').splitlines(), 1)
              if re.match(r'\s*=\s', line)]
    assert broken == [], f'{script.name}: lines {broken} start with "="'


def test_every_harness_is_covered():
    assert {path.name for path in HARNESSES} >= {'test-antibypass-sandbox.ps1', 'test-dns-sandbox.ps1',
                                                 'test-msi-sandbox.ps1', 'test-safesearch-sandbox.ps1'}
