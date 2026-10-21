"""Admin authentication for the management API / console.

Passwords are stored as salted PBKDF2-SHA256 hashes. Sessions are stateless
HMAC-signed bearer tokens (no server-side session store needed): the token
carries the username, role and expiry, signed with a per-process (or configured)
secret. This protects `/api/v1/*`; the endpoint channel (`/fct/api/*`) has its
own device-level auth and is not gated by admin login.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Optional

from .stores import AdminStore, InMemoryAdminStore


def hash_password(password: str, *, salt: bytes | None = None, iterations: int = 200_000) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iters)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class AdminService:
    """In-memory admin registry + stateless token issuing/verification."""

    def __init__(
        self, secret: bytes | str | None = None, *, store: AdminStore | None = None
    ) -> None:
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        self._secret: bytes = secret or secrets.token_bytes(32)
        self._store: AdminStore = store or InMemoryAdminStore()

    def add_admin(self, username: str, password: str, role: str = "admin") -> None:
        self._store.put(username, hash_password(password), role)

    def has_admins(self) -> bool:
        """Whether any admin exists. Until one does, the API runs open (setup mode)."""
        return self._store.has_any()

    def authenticate(self, username: str, password: str) -> Optional[str]:
        """Return the admin's role on success, else None."""
        record = self._store.get(username)
        if record is None:
            return None
        pw_hash, role = record
        return role if verify_password(password, pw_hash) else None

    def issue_token(self, username: str, role: str, *, ttl_seconds: int = 3600) -> str:
        payload = {"u": username, "r": role, "exp": int(time.time()) + ttl_seconds}
        raw = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        return f"{raw}.{self._sign(raw)}"

    def verify_token(self, token: str) -> Optional[dict[str, str]]:
        try:
            raw, sig = token.split(".", 1)
        except ValueError:
            return None
        if not hmac.compare_digest(sig, self._sign(raw)):
            return None
        try:
            payload = json.loads(_b64url_decode(raw))
        except (ValueError, json.JSONDecodeError):
            return None
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return {"username": payload.get("u", ""), "role": payload.get("r", "")}

    def _sign(self, raw: str) -> str:
        return hmac.new(self._secret, raw.encode("ascii"), hashlib.sha256).hexdigest()
