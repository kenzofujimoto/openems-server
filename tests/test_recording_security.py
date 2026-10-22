"""Capture files must remain useful without persisting endpoint credentials."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from urllib.parse import parse_qs

import pytest

from app.recording import RecorderMiddleware, _record_line
from tools.analyze_capture import main


def scope(content_type: str = "application/json") -> dict:
    return {
        "type": "http", "method": "POST", "path": "/fct/api/register/",
        "query_string": b"devid=public&invitation=query-secret&key=key-secret&client_id=id-secret",
        "headers": [(b"content-type", content_type.encode()),
                    (b"authorization", b"Bearer auth-secret"), (b"cookie", b"session=cookie-secret")],
    }


@pytest.mark.parametrize("field", ["invitation", "key", "client_id", "device_token", "password", "csrf_token", "Authorization", "cookies"])
def test_capture_redacts_nested_credentials_and_query(field: str) -> None:
    record = json.loads(_record_line(scope(), json.dumps({"devid": "public", "nested": [{field: "body-secret"}]}).encode()))
    rendered = json.dumps(record)
    assert "body-secret" not in rendered
    assert all(secret not in rendered for secret in ["query-secret", "key-secret", "id-secret", "auth-secret", "cookie-secret"])
    assert json.loads(record["body_text"])["devid"] == "public"
    assert parse_qs(record["query"])["invitation"] == ["<redacted>"]


def test_form_and_unstructured_bodies_are_safe() -> None:
    form = json.loads(_record_line(scope("application/x-www-form-urlencoded"), b"devid=public&device_token=secret&key=second"))
    assert "secret" not in json.dumps(form)
    assert parse_qs(form["body_text"])["devid"] == ["public"]
    for content_type, body in [("application/json", b'{"key":"malformed-secret"'), ("application/octet-stream", b"binary-secret\xff"), ("text/plain", b"plain-secret")]:
        assert "secret" not in _record_line(scope(content_type), body)


def run_capture(path: Path, *, count: int = 1, **options) -> RecorderMiddleware:
    async def downstream(request_scope, receive, send):
        message = await receive()
        assert message["body"] == b'{"devid":"public"}'
    middleware = RecorderMiddleware(downstream, str(path), **options)
    async def run():
        for _ in range(count):
            async def receive():
                return {"type": "http.request", "body": b'{"devid":"public"}', "more_body": False}
            await middleware(scope(), receive, None)
    asyncio.run(run())
    return middleware


def test_capture_rotation_bounds_disk_use(tmp_path: Path) -> None:
    path = tmp_path / "capture.jsonl"
    run_capture(path, count=20, max_bytes=1200, backup_count=2)
    files = list(tmp_path.iterdir())
    assert len(files) == 3
    assert all(file.stat().st_size <= 1200 for file in files)
    assert all(json.loads(line) for file in files for line in file.read_text().splitlines())


def test_capture_errors_are_observable_without_breaking_request(tmp_path: Path, caplog) -> None:
    middleware = run_capture(tmp_path / "missing" / "capture.jsonl")
    assert middleware.write_failures == 1
    assert "Capture write failed" in caplog.text


def test_oversized_capture_is_omitted_but_request_reaches_application(tmp_path: Path) -> None:
    path = tmp_path / "capture.jsonl"
    run_capture(path, max_body_bytes=4)
    record = json.loads(path.read_text())
    assert record["body_truncated"] is True
    assert "body_text" not in record


def test_analyzer_redacts_legacy_capture(tmp_path: Path, capsys) -> None:
    path = tmp_path / "legacy.jsonl"
    path.write_text(json.dumps({"method": "POST", "path": "/fct/api/register/", "body_text": '{"devid":"public","nested":{"device_token":"legacy-secret"}}'}) + "\n")
    assert main(str(path)) == 0
    output = capsys.readouterr().out
    assert "legacy-secret" not in output
    assert "public" in output
