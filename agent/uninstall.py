"""One-time uninstall codes (tamper-protection.md, decisions 5 and 7).

Each registration's secret is HMAC-SHA256(master key, client id): the server derives it, the agent
receives it once and checks codes offline, and the offline tool can mint codes without the server.
Codes follow the HOTP construction (RFC 4226: HMAC over a big-endian 8-byte counter) with SHA-256 and
a 50-bit output written as 10 Crockford base32 symbols, so they are typed without ambiguity.
"""

from __future__ import annotations

import hashlib
import hmac

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
CODE_LENGTH = 10
# Counters accepted above the last one used, so unused codes generated in the panel stay valid.
WINDOW = 20
MIN_MASTER_KEY = 32
_SECRET_LABEL = b"openems-uninstall-v1\x00"
_RELEASE_LABEL = b"openems-release-v1"
_LOOKALIKES = str.maketrans({"O": "0", "I": "1", "L": "1"})


def derive_secret(master_key: bytes, client_id: str) -> bytes:
    if len(master_key) < MIN_MASTER_KEY:
        raise ValueError(f"the uninstall master key must have at least {MIN_MASTER_KEY} bytes")
    if not client_id:
        raise ValueError("a client id is required")
    return hmac.new(master_key, _SECRET_LABEL + client_id.encode("utf-8"), hashlib.sha256).digest()


def code(secret: bytes, counter: int) -> str:
    if not 0 < counter < 2**63:
        raise ValueError("counter must be positive")
    mac = hmac.new(secret, counter.to_bytes(8, "big"), hashlib.sha256).digest()
    value = int.from_bytes(mac[:8], "big") >> (64 - 5 * CODE_LENGTH)
    symbols = "".join(ALPHABET[(value >> (5 * (CODE_LENGTH - 1 - index))) & 31] for index in range(CODE_LENGTH))
    return f"{symbols[:5]}-{symbols[5:]}"


def normalize(text: str) -> str | None:
    """Code as typed (any case, spaces or dashes, O/I/L lookalikes) to its 10 symbols, or None."""
    cleaned = text.upper().replace("-", "").replace(" ", "").translate(_LOOKALIKES)
    if len(cleaned) != CODE_LENGTH or any(symbol not in ALPHABET for symbol in cleaned):
        return None
    return cleaned


def verify(secret: bytes, typed: str, last_used: int, window: int = WINDOW) -> int | None:
    """Counter of a valid unused code (last_used < counter <= last_used + window), or None."""
    wanted = normalize(typed)
    if wanted is None:
        return None
    for counter in range(last_used + 1, last_used + window + 1):
        if hmac.compare_digest(code(secret, counter).replace("-", ""), wanted):
            return counter
    return None


def release_token(secret: bytes) -> str:
    """Proof that the server released removal without a code for this registration."""
    return hmac.new(secret, _RELEASE_LABEL, hashlib.sha256).hexdigest()
