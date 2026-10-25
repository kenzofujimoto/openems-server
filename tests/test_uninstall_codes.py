"""One-time uninstall codes (tamper-protection.md, decisions 5 and 7): shared reference implementation."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

from agent.uninstall import WINDOW, code, derive_secret, normalize, release_token, verify

ROOT = Path(__file__).resolve().parent.parent
MASTER = b"test-only-master-key-0123456789abcdef"
CODE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$")


def test_each_registration_gets_its_own_secret_from_the_master_key():
    first = derive_secret(MASTER, "client-1")
    assert first == derive_secret(MASTER, "client-1") and len(first) == 32
    assert first != derive_secret(MASTER, "client-2")
    assert first != derive_secret(MASTER + b"x", "client-1")
    with pytest.raises(ValueError):
        derive_secret(b"too short", "client-1")
    with pytest.raises(ValueError):
        derive_secret(MASTER, "")


def test_codes_are_ten_unambiguous_symbols_per_counter():
    secret = derive_secret(MASTER, "client-1")
    codes = [code(secret, counter) for counter in range(1, 50)]
    assert all(CODE.match(item) for item in codes)
    assert len(set(codes)) == len(codes)
    assert code(secret, 1) == code(secret, 1)
    with pytest.raises(ValueError):
        code(secret, 0)


def test_typed_codes_are_normalized():
    secret = derive_secret(MASTER, "client-1")
    typed = code(secret, 1)
    assert normalize(typed.lower().replace("-", " ")) == typed.replace("-", "")
    assert normalize("O0IL1-ABCDE") == "00111ABCDE", "O reads as zero, I and L as one"
    for invalid in ("", "ABCDE-FGHJ", "ABCDE-FGHJKM", "ABCDE-FGHJU", "ABCDE-FGH!K"):
        assert normalize(invalid) is None


def test_a_code_is_accepted_once_within_the_window_above_the_last_used_counter():
    secret = derive_secret(MASTER, "client-1")
    assert verify(secret, code(secret, 1), last_used=0) == 1
    assert verify(secret, code(secret, WINDOW), last_used=0) == WINDOW
    assert verify(secret, code(secret, WINDOW + 1), last_used=0) is None
    assert verify(secret, code(secret, 3), last_used=3) is None, "already used"
    assert verify(secret, code(secret, 4), last_used=3) == 4
    assert verify(secret, "00000-00000", last_used=0) is None
    assert verify(derive_secret(MASTER, "client-2"), code(secret, 1), last_used=0) is None
    assert verify(secret, "not a code", last_used=0) is None


def test_release_tokens_are_bound_to_one_machine_secret():
    first, second = derive_secret(MASTER, "client-1"), derive_secret(MASTER, "client-2")
    assert re.fullmatch(r"[0-9a-f]{64}", release_token(first))
    assert release_token(first) != release_token(second)


def _generator():
    spec = importlib.util.spec_from_file_location("gen_uninstall_vectors", ROOT / "tools" / "gen_uninstall_vectors.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_committed_vectors_match_the_reference():
    committed = (ROOT / "contract" / "uninstall-vectors.json").read_text(encoding="utf-8")
    assert committed == _generator().render(), "run: python tools/gen_uninstall_vectors.py"
