"""Category files: b"OEMSCAT1", a big-endian u32 count, then sorted unique u64 domain hashes.

The server builds them from the UT1 lists; agents download only the categories their policy uses
and check them against the SHA-256 digest published in the manifest.
"""

from __future__ import annotations

from collections.abc import Iterable
from itertools import pairwise

try:
    from .policy import domain_hash
except ImportError:
    from policy import domain_hash

MAGIC = b"OEMSCAT1"
MAX_ENTRIES = 20_000_000


def build_category_file(domains: Iterable[str]) -> bytes:
    """Hash every valid domain; invalid list entries (comments, IPs, wildcards) are skipped."""
    hashes: set[int] = set()
    for domain in domains:
        try:
            hashes.add(domain_hash(domain))
        except ValueError:
            continue
    ordered = sorted(hashes)
    return MAGIC + len(ordered).to_bytes(4, "big") + b"".join(value.to_bytes(8, "big") for value in ordered)


def parse_category_file(data: bytes) -> list[int]:
    if len(data) < 12 or data[:8] != MAGIC:
        raise ValueError("not an openems category file")
    count = int.from_bytes(data[8:12], "big")
    if count > MAX_ENTRIES or len(data) != 12 + 8 * count:
        raise ValueError("category file length does not match its count")
    values = [int.from_bytes(data[offset:offset + 8], "big") for offset in range(12, len(data), 8)]
    if any(previous >= current for previous, current in pairwise(values)):
        raise ValueError("category hashes must be sorted and unique")
    return values
