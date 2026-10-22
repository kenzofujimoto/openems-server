"""Admin authentication with revocable sessions, explicit roles and login limits."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

from .sessions import AdminSession, InMemorySessionStore, SessionStore
from .stores import AdminStore, InMemoryAdminStore

_PERMISSIONS = {
    "viewer": frozenset({"read"}),
    "admin": frozenset({"read", "write", "manage_idp"}),
    "superadmin": frozenset({"read", "write", "manage_idp"}),
}


class LoginRateLimited(Exception):
    """Login must wait; callers should return HTTP 429 with Retry-After."""

    def __init__(self, retry_after: int) -> None:
        super().__init__("too many login attempts")
        self.retry_after = retry_after


def hash_password(
    password: str, *, salt: bytes | None = None, iterations: int = 200_000
) -> str:
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
    except (ValueError, TypeError, OverflowError):
        return False


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _fingerprint(record: tuple[str, str]) -> str:
    return hashlib.sha256((record[0] + "\0" + record[1]).encode()).hexdigest()


class AdminService:
    """Token signatures authenticate opaque IDs; server-side state permits revocation."""

    def __init__(
        self,
        secret: bytes | str | None = None,
        *,
        store: AdminStore | None = None,
        session_store: SessionStore | None = None,
        login_max_attempts: int = 5,
        login_window_seconds: int = 300,
    ) -> None:
        if login_max_attempts < 1 or login_window_seconds < 1:
            raise ValueError("login limits must be positive")
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        self._secret = secret or secrets.token_bytes(32)
        self._store = store if store is not None else InMemoryAdminStore()
        self._sessions = (
            session_store if session_store is not None else InMemorySessionStore()
        )
        self._login_max_attempts = login_max_attempts
        self._login_window_seconds = login_window_seconds
        # Unknown usernames still perform password hashing after the same rate-limit gate.
        self._dummy_hash = hash_password(secrets.token_urlsafe(32))

    def add_admin(self, username: str, password: str, role: str = "admin") -> None:
        if not isinstance(username, str) or not username or len(username) > 256:
            raise ValueError("a username of at most 256 characters is required")
        if not isinstance(password, str) or not password or len(password) > 4096:
            raise ValueError("a password of at most 4096 characters is required")
        if role not in _PERMISSIONS:
            raise ValueError("unknown admin role")
        self._store.put(username, hash_password(password), role)

    def has_admins(self) -> bool:
        return self._store.has_any()

    @staticmethod
    def is_allowed(role: str, action: str) -> bool:
        return action in _PERMISSIONS.get(role, frozenset())

    def authenticate(self, username: str, password: str) -> str | None:
        if not isinstance(username, str) or not isinstance(password, str):
            return None
        if len(username) > 256 or len(password) > 4096:
            return None
        record = self._store.get(username)
        valid = verify_password(password, record[0] if record else self._dummy_hash)
        if record is None or not valid or record[1] not in _PERMISSIONS:
            return None
        return record[1]

    def authenticate_with_rate_limit(
        self, username: str, password: str, ip: str
    ) -> str | None:
        now = time.time()
        key = "login:" + hashlib.sha256(json.dumps([username, ip]).encode()).hexdigest()
        ip_key = "ip:" + hashlib.sha256(ip.encode()).hexdigest()
        for bucket, attempts in (
            (key, self._login_max_attempts),
            (ip_key, self._login_max_attempts * 10),
        ):
            retry = self._sessions.consume_login_attempt(
                bucket,
                now=now,
                window_seconds=self._login_window_seconds,
                max_attempts=attempts,
            )
            if retry:
                raise LoginRateLimited(retry)
        role = self.authenticate(username, password)
        if role is not None:
            self._sessions.reset_login(key)
        return role

    def issue_session(
        self, username: str, role: str, *, ttl_seconds: int = 3600
    ) -> dict[str, str]:
        record = self._store.get(username)
        if record is None or record[1] != role or role not in _PERMISSIONS:
            raise ValueError("cannot issue a session for an unknown account or role")
        if type(ttl_seconds) is not int or ttl_seconds > 86_400:
            raise ValueError(
                "session TTL must be an integer no greater than 86400 seconds"
            )
        now = int(time.time())
        session = AdminSession(
            sid=secrets.token_hex(32),
            username=username,
            role=role,
            credential_fingerprint=_fingerprint(record),
            csrf_token=secrets.token_urlsafe(32),
            created_at=now,
            expires_at=now + ttl_seconds,
        )
        self._sessions.put(session)
        raw = _b64url(
            json.dumps(
                {"v": 1, "sid": session.sid, "exp": session.expires_at},
                separators=(",", ":"),
            ).encode()
        )
        return {"token": f"{raw}.{self._sign(raw)}", "csrf_token": session.csrf_token}

    def issue_token(self, username: str, role: str, *, ttl_seconds: int = 3600) -> str:
        return self.issue_session(username, role, ttl_seconds=ttl_seconds)["token"]

    def _session(self, token: str) -> AdminSession | None:
        if not isinstance(token, str) or len(token) > 4096:
            return None
        try:
            raw, sig = token.split(".", 1)
            if not hmac.compare_digest(
                sig.encode("ascii"), self._sign(raw).encode("ascii")
            ):
                return None
            payload = json.loads(
                base64.b64decode(
                    raw + "=" * (-len(raw) % 4),
                    altchars=b"-_",
                    validate=True,
                )
            )
        except (ValueError, TypeError, UnicodeError):
            return None
        if not isinstance(payload, dict) or set(payload) != {"v", "sid", "exp"}:
            return None
        if type(payload["v"]) is not int or payload["v"] != 1:
            return None
        if type(payload["exp"]) is not int or payload["exp"] <= time.time():
            return None
        sid = payload["sid"]
        if (
            not isinstance(sid, str)
            or len(sid) != 64
            or any(c not in "0123456789abcdef" for c in sid)
        ):
            return None
        session = self._sessions.get(sid)
        if session is None or session.expires_at != payload["exp"]:
            return None
        record = self._store.get(session.username)
        if (
            record is None
            or session.role not in _PERMISSIONS
            or record[1] != session.role
            or not hmac.compare_digest(
                session.credential_fingerprint, _fingerprint(record)
            )
        ):
            self._sessions.revoke(sid)
            return None
        return session

    def verify_token(self, token: str) -> dict[str, str] | None:
        session = self._session(token)
        return {"username": session.username, "role": session.role} if session else None

    def csrf_for_token(self, token: str) -> str | None:
        session = self._session(token)
        return session.csrf_token if session else None

    def verify_csrf(self, token: str, supplied: str) -> bool:
        expected = self.csrf_for_token(token)
        return bool(
            expected
            and isinstance(supplied, str)
            and hmac.compare_digest(expected.encode(), supplied.encode())
        )

    def revoke_token(self, token: str) -> bool:
        session = self._session(token)
        return self._sessions.revoke(session.sid) if session else False

    def _sign(self, raw: str) -> str:
        return hmac.new(self._secret, raw.encode("ascii"), hashlib.sha256).hexdigest()
