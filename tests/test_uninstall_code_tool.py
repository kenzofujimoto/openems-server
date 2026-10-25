"""Offline uninstall code tool (tamper-protection.md, decision 7b): no server, no database, no network."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "uninstall_code.py"
VECTORS = json.loads((ROOT / "contract" / "uninstall-vectors.json").read_text(encoding="utf-8"))
MASTER = VECTORS["master_key"]
CLIENT = VECTORS["secrets"][0]


def run(*arguments: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(TOOL), *arguments], input=stdin, capture_output=True,
                          text=True, encoding="utf-8", timeout=60, check=False)


@pytest.fixture()
def key_file(tmp_path: Path) -> Path:
    path = tmp_path / "master.key"
    path.write_text(MASTER + "\n", encoding="utf-8")
    return path


def test_prints_the_first_code_of_a_registration_by_default(key_file: Path):
    result = run("--master-key-file", str(key_file), "--client-id", CLIENT["client_id"])
    assert result.returncode == 0, result.stderr
    assert result.stdout == CLIENT["codes"][0]["code"] + "\n"


@pytest.mark.parametrize("entry", [entry for item in VECTORS["secrets"] for entry in
                                   ({"client_id": item["client_id"], **code} for code in item["codes"])],
                         ids=lambda entry: f"{entry['client_id']}-{entry['counter']}")
def test_codes_match_the_shared_vectors(key_file: Path, entry: dict):
    result = run("--master-key-file", str(key_file), "--client-id", entry["client_id"],
                 "--counter", str(entry["counter"]))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == entry["code"]


def test_reads_the_master_key_from_standard_input():
    result = run("--master-key-file", "-", "--client-id", CLIENT["client_id"], stdin=f"  {MASTER}\r\n")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == CLIENT["codes"][0]["code"]


def test_accepts_a_key_file_saved_with_a_byte_order_mark(tmp_path: Path):
    path = tmp_path / "notepad.key"
    path.write_text(MASTER, encoding="utf-8-sig")
    result = run("--master-key-file", str(path), "--client-id", CLIENT["client_id"])
    assert result.stdout.strip() == CLIENT["codes"][0]["code"], result.stderr


def test_count_lists_consecutive_counters_to_cover_the_window(key_file: Path):
    result = run("--master-key-file", str(key_file), "--client-id", CLIENT["client_id"], "--counter", "20",
                 "--count", "2")
    assert result.returncode == 0, result.stderr
    lines = [line.split() for line in result.stdout.splitlines()]
    expected = {code["counter"]: code["code"] for code in CLIENT["codes"]}
    assert lines == [["20", expected[20]], ["21", expected[21]]]


def test_count_covers_at_most_one_window(key_file: Path):
    full = run("--master-key-file", str(key_file), "--client-id", CLIENT["client_id"], "--count", "20")
    assert full.returncode == 0 and len(full.stdout.splitlines()) == 20
    for invalid in ("0", "21"):
        result = run("--master-key-file", str(key_file), "--client-id", CLIENT["client_id"], "--count", invalid)
        assert result.returncode != 0 and "--count" in result.stderr


@pytest.mark.parametrize("arguments", [
    ("--client-id", ""),
    ("--client-id", "   "),
    ("--client-id", "client-1", "--counter", "0"),
    ("--client-id", "client-1", "--counter", "-1"),
    ("--client-id", "client-1", "--counter", str(2**63)),
    ("--client-id", "client-1", "--counter", str(2**63 - 1), "--count", "2"),
])
def test_invalid_input_fails_with_a_message_and_no_traceback(key_file: Path, arguments: tuple[str, ...]):
    result = run("--master-key-file", str(key_file), *arguments)
    assert result.returncode != 0 and result.stdout == ""
    assert result.stderr.strip() and "Traceback" not in result.stderr


def test_a_short_or_missing_key_is_refused_without_echoing_it(tmp_path: Path):
    short = "short-but-secret"
    path = tmp_path / "short.key"
    path.write_text(short, encoding="utf-8")
    for arguments, stdin in [(("--master-key-file", str(path)), None), (("--master-key-file", "-"), short),
                             (("--master-key-file", "-"), ""), (("--master-key-file", str(tmp_path / "absent")), None)]:
        result = run(*arguments, "--client-id", "client-1", stdin=stdin)
        assert result.returncode != 0 and result.stdout == ""
        assert "Traceback" not in result.stderr and short not in result.stderr


def test_a_key_file_that_is_not_text_is_refused(tmp_path: Path):
    path = tmp_path / "binary.key"
    path.write_bytes(b"\xff\xfe" + bytes(range(128, 200)))
    result = run("--master-key-file", str(path), "--client-id", "client-1")
    assert result.returncode != 0 and "Traceback" not in result.stderr


def test_the_master_key_cannot_be_given_on_the_command_line():
    for option in ("--master-key", "--key", "--master"):
        result = run(option, MASTER, "--client-id", "client-1")
        assert result.returncode != 0 and result.stdout == ""
        assert MASTER not in result.stderr, f"{option} must not echo the key"


def test_the_master_key_never_reaches_the_output(key_file: Path):
    result = run("--master-key-file", str(key_file), "--client-id", "client-1", "--count", "20")
    assert MASTER not in result.stdout + result.stderr
