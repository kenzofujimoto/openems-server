#!/usr/bin/env python3
"""Generate one-time uninstall codes without the server (tamper-protection.md, decision 7b).

Needs only the master key and the machine's client_id (in C:\\ProgramData\\openems\\state.json):
no database and no network. The key is read from a file or from standard input (--master-key-file -),
never from the command line, so it stays out of shell history and process listings.

The agent accepts codes above the last counter it used, up to 20 ahead. Without the server the last
counter is unknown: start at 1 with --count 20, and if every code is refused, continue at --counter 21.

    python tools/uninstall_code.py --master-key-file - --client-id 0123abcd... --count 20
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent"))

from uninstall import WINDOW, code, derive_secret, master_key_from_text

MAX_COUNTER = 2**63 - 1


def read_key_text(source: str) -> str:
    """Key file contents, or standard input for "-"; errors never include the path or the contents."""
    try:
        data = sys.stdin.buffer.read() if source == "-" else Path(source).read_bytes()
    except OSError:
        raise ValueError("could not read the master key file") from None
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("the master key file must be UTF-8 text") from None


def generate(master_key: bytes, client_id: str, counter: int, count: int) -> list[tuple[int, str]]:
    secret = derive_secret(master_key, client_id)
    return [(value, code(secret, value)) for value in range(counter, counter + count)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0], allow_abbrev=False)
    parser.add_argument("--master-key-file", required=True, metavar="PATH",
                        help='file holding the master key, or "-" to read it from standard input')
    parser.add_argument("--client-id", required=True, help="the machine's client_id (state.json)")
    parser.add_argument("--counter", type=int, default=1, help="first counter (default 1)")
    parser.add_argument("--count", type=int, default=1, help=f"codes to list, 1 to {WINDOW} (default 1)")
    args, unknown = parser.parse_known_args()
    if unknown:
        # Never echo unknown arguments: a key typed on the command line would end up in the error.
        parser.error("unrecognized arguments (the master key is read only through --master-key-file)")
    client_id = args.client_id.strip()
    if not client_id:
        parser.error("--client-id must not be empty")
    if not 1 <= args.count <= WINDOW:
        parser.error(f"--count must be between 1 and {WINDOW}")
    if not 1 <= args.counter <= MAX_COUNTER - args.count + 1:
        parser.error(f"--counter must be between 1 and {MAX_COUNTER} for every listed code")
    try:
        master_key = master_key_from_text(read_key_text(args.master_key_file))
        codes = generate(master_key, client_id, args.counter, args.count)
    except ValueError as error:
        parser.error(str(error))
    if args.count == 1:
        print(codes[0][1])
    else:
        width = len(str(codes[-1][0]))
        for counter, value in codes:
            print(f"{counter:>{width}}  {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
