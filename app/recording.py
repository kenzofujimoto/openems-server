"""Traffic recorder for the endpoint channel.

A pure-ASGI middleware that tees the request body of every endpoint-channel call
(``/fct/api/...`` by default) to a JSONL file, then replays it downstream so the
route still sees it. Point a lab FortiClient-style endpoint at this server and
every register/refresh/keepalive/telemetry body is captured in cleartext — the
server terminates TLS, so there is no certificate-pinning fight and no need to
decrypt anything.

Each line is one request:
    {"ts", "method", "path", "query", "client", "content_type",
     "headers" (sensitive ones redacted), "body_text" or "body_b64"}

Enable via create_app(record_path=...) or the OPENEMS_RECORD env var. Recording
writes request metadata and bodies to disk, so only turn it on in a lab.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any

_SENSITIVE = {"authorization", "cookie", "set-cookie", "proxy-authorization"}


def _record_line(scope: dict[str, Any], body: bytes) -> str:
    headers: dict[str, str] = {}
    content_type = ""
    for k, v in scope.get("headers", []):
        name = k.decode("latin1").lower()
        value = v.decode("latin1")
        if name == "content-type":
            content_type = value
        headers[name] = "<redacted>" if name in _SENSITIVE else value

    client = scope.get("client")
    entry: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "method": scope.get("method", ""),
        "path": scope.get("path", ""),
        "query": scope.get("query_string", b"").decode("latin1"),
        "client": client[0] if client else "",
        "content_type": content_type,
        "headers": headers,
    }
    try:
        entry["body_text"] = body.decode("utf-8")
    except UnicodeDecodeError:
        entry["body_b64"] = base64.b64encode(body).decode("ascii")
    return json.dumps(entry, ensure_ascii=False)


class RecorderMiddleware:
    def __init__(self, app, out_path: str, prefix: str = "/fct/api/") -> None:
        self.app = app
        self.out_path = out_path
        self.prefix = prefix

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or not scope.get("path", "").startswith(self.prefix):
            return await self.app(scope, receive, send)

        body = b""
        messages = []
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] == "http.request":
                body += message.get("body", b"")
                if not message.get("more_body", False):
                    break
            else:  # http.disconnect
                break

        try:
            with open(self.out_path, "a", encoding="utf-8") as fh:
                fh.write(_record_line(scope, body) + "\n")
        except OSError:
            pass  # never let recording break request handling

        sent = False

        async def replay_receive():
            nonlocal sent
            if not sent:
                sent = True
                # replay buffered messages as one body chunk
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)
