"""Bounded, credential-redacted lab captures of the endpoint channel.

Bodies are retained only when structured JSON or URL-encoded forms can be
redacted safely. Binary, malformed and oversized bodies are omitted. Captures
still contain device identifiers; operators must restrict file access.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode

_LOG = logging.getLogger(__name__)
_REDACTED = "<redacted>"
_SENSITIVE = {
    "authorization", "proxyauthorization", "cookie", "cookies", "setcookie",
    "key", "apikey", "clientid", "invitation", "invitationcode", "invite",
    "password", "passwd", "credential", "credentials", "samlresponse",
    "assertion", "certificate", "privatekey", "session", "sessionid",
}


def _sensitive(name: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", name.casefold())
    return normalized in _SENSITIVE or normalized.endswith(("token", "secret", "password", "apikey"))


def redact(value: Any) -> Any:
    """Redact credentials recursively without modifying public device fields."""
    if isinstance(value, dict):
        return {key: _REDACTED if _sensitive(str(key)) else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str) and value.lstrip().startswith(("{", "[")):
        try:
            return json.dumps(redact(json.loads(value)), ensure_ascii=False)
        except (ValueError, RecursionError):
            # An apparent serialized object cannot be safely inspected.
            return _REDACTED
    return value


def redact_form(value: str) -> str:
    return urlencode([(key, _REDACTED if _sensitive(key) else redact(item)) for key, item in parse_qsl(value, keep_blank_values=True)])


def safe_body(body: bytes, content_type: str = "") -> str | None:
    """Return only a structured body that was successfully redacted."""
    try:
        decoded = body.decode("utf-8")
        if "application/x-www-form-urlencoded" in content_type.casefold():
            return redact_form(decoded)
        parsed = json.loads(decoded)
        if isinstance(parsed, (dict, list)):
            return json.dumps(redact(parsed), ensure_ascii=False)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    return None


def _record_line(scope: dict[str, Any], body: bytes, *, truncated: bool = False) -> str:
    headers: dict[str, str] = {}
    content_type = ""
    for key, raw in scope.get("headers", []):
        name, value = key.decode("latin1").lower(), raw.decode("latin1")
        if name == "content-type":
            content_type = value
        headers[name] = _REDACTED if _sensitive(name) else value
    client = scope.get("client")
    entry: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(),
        "method": scope.get("method", ""), "path": scope.get("path", ""),
        "query": redact_form(scope.get("query_string", b"").decode("latin1")),
        "client": client[0] if client else "", "content_type": content_type, "headers": headers,
    }
    if truncated:
        entry["body_truncated"] = True
    else:
        sanitized = safe_body(body, content_type)
        if sanitized is None:
            entry["body_omitted"] = True
        else:
            entry["body_text"] = sanitized
    return json.dumps(entry, ensure_ascii=False)


class RecorderMiddleware:
    def __init__(
        self, app, out_path: str, prefix: str = "/fct/api/", *,
        max_body_bytes: int = 65536, max_bytes: int = 1048576, backup_count: int = 3,
    ) -> None:
        if max_body_bytes < 1 or max_bytes < 512 or backup_count < 1:
            raise ValueError("Capture limits must be positive (max_bytes >= 512)")
        self.app = app
        self.out_path = out_path
        self.prefix = prefix
        self.max_body_bytes = max_body_bytes
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.write_failures = 0
        self._lock = threading.Lock()

    def _write(self, line: str) -> None:
        payload = (line + "\n").encode("utf-8")
        if len(payload) > self.max_bytes:
            # Request metadata can also be large. Retain an explicit marker only.
            payload = (json.dumps({"ts": datetime.now(UTC).isoformat(), "record_omitted": "size limit"}) + "\n").encode()
        with self._lock:
            path = Path(self.out_path)
            if path.exists() and path.stat().st_size + len(payload) > self.max_bytes:
                oldest = Path(f"{path}.{self.backup_count}")
                oldest.unlink(missing_ok=True)
                for number in range(self.backup_count - 1, 0, -1):
                    source = Path(f"{path}.{number}")
                    if source.exists():
                        source.replace(f"{path}.{number + 1}")
                path.replace(f"{path}.1")
            with path.open("ab") as handle:
                handle.write(payload)

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or not scope.get("path", "").startswith(self.prefix):
            return await self.app(scope, receive, send)
        body = bytearray()
        truncated = False

        async def capture_receive():
            nonlocal truncated
            message = await receive()
            if message.get("type") == "http.request":
                chunk = message.get("body", b"")
                available = self.max_body_bytes - len(body)
                body.extend(chunk[:available])
                truncated |= len(chunk) > available
            return message

        try:
            await self.app(scope, capture_receive, send)
        finally:
            try:
                self._write(_record_line(scope, bytes(body), truncated=truncated))
            except (OSError, ValueError, RecursionError) as exc:
                self.write_failures += 1
                # Do not include exception text, paths or credentials in logs.
                _LOG.warning("Capture write failed (%s)", type(exc).__name__)
