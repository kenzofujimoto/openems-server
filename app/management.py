"""Administrative account, invitation and trusted-artifact delivery routes."""
from __future__ import annotations

import hashlib
import io
import ipaddress
import re
import zipfile
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse

from .auth import AdminService
from .schemas import AdminCreatePayload, AdminUpdatePayload, InvitationPayload
from .service import EmsService


def attach_management_routes(app: FastAPI, service: EmsService, admin: AdminService, record: Callable,
                             retention_days: int, installer_path: Path | None, public_base_url: str | None) -> None:
    def require_writer(request: Request) -> dict[str, str]:
        claims = getattr(request.state, "admin", {})
        if claims.get("role") not in {"admin", "superadmin"}:
            raise HTTPException(status_code=403, detail="administrator permission required")
        return claims

    def artifact() -> Path | None:
        if installer_path is None:
            return None
        try:
            path = installer_path.resolve(strict=True)
            if path.suffix.lower() != ".msi" or not path.is_file() or path.stat().st_size > 128 * 1024 * 1024:
                return None
            return path
        except OSError:
            return None

    @app.get("/api/v1/admins")
    def accounts(request: Request):
        require_writer(request)
        return admin.accounts()

    @app.post("/api/v1/admins")
    def create_account(payload: AdminCreatePayload, request: Request):
        claims = require_writer(request)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}", payload.username):
            raise HTTPException(status_code=422, detail="username must contain letters, numbers, dots, @, underscores or hyphens")
        if not admin.manage_account(payload.username, payload.password, payload.role, create=True, actor_role=claims["role"]):
            raise HTTPException(status_code=409, detail="account already exists")
        record(request, "admin.create", payload.username, role=payload.role)
        return {"username": payload.username, "role": payload.role}

    @app.put("/api/v1/admins/{username}")
    def update_account(username: str, payload: AdminUpdatePayload, request: Request):
        claims = require_writer(request)
        try:
            changed = admin.manage_account(username, payload.password, payload.role, actor_role=claims["role"])
        except PermissionError as error:
            raise HTTPException(status_code=403, detail="superadministrator is protected") from error
        except ValueError as error:
            raise HTTPException(status_code=409, detail="the last administrator cannot be demoted") from error
        if not changed:
            raise HTTPException(status_code=404, detail="unknown account")
        record(request, "admin.update", username, password_changed=payload.password is not None, role=payload.role)
        return next(account for account in admin.accounts() if account["username"] == username)

    @app.delete("/api/v1/admins/{username}")
    def delete_account(username: str, request: Request):
        claims = require_writer(request)
        if username == claims["username"]:
            raise HTTPException(status_code=409, detail="you cannot delete your own account")
        try:
            removed = admin.manage_account(username, delete=True, actor_role=claims["role"])
        except PermissionError as error:
            raise HTTPException(status_code=403, detail="superadministrator is protected") from error
        except ValueError as error:
            raise HTTPException(status_code=409, detail="the last administrator cannot be removed") from error
        if not removed:
            raise HTTPException(status_code=404, detail="unknown account")
        record(request, "admin.delete", username)
        return {"removed": username}

    @app.get("/api/v1/enrollment/invitations")
    def invitations(request: Request):
        require_writer(request)
        return service.list_invitations()

    @app.delete("/api/v1/enrollment/invitations/{identifier}")
    def revoke_invitation(identifier: str, request: Request):
        require_writer(request)
        if not re.fullmatch(r"[a-f0-9]{64}", identifier) or not service.revoke_invitation(identifier):
            raise HTTPException(status_code=404, detail="unknown invitation")
        record(request, "enrollment.invitation.revoke", identifier)
        return {"removed": identifier}

    @app.get("/api/v1/settings")
    def settings():
        return {"event_retention_days": retention_days, "installer_available": artifact() is not None,
                "installer_configuration": "operator", "server_version": "0.2.0"}

    @app.get("/api/v1/installers/windows")
    def installer_metadata(request: Request):
        require_writer(request)
        path = artifact()
        if path is None:
            return {"available": False}
        try:
            with path.open("rb") as source:
                digest = hashlib.file_digest(source, "sha256").hexdigest()
            return {"available": True, "filename": "openems-agent.msi", "sha256": digest,
                    "size": path.stat().st_size, "download_url": "/api/v1/installers/windows/download",
                    "bundle_url": "/api/v1/installers/windows/bundle"}
        except OSError as error:
            raise HTTPException(status_code=503, detail="installer artifact is unavailable") from error

    @app.get("/api/v1/installers/windows/download")
    def installer_download(request: Request):
        require_writer(request)
        path = artifact()
        if path is None:
            raise HTTPException(status_code=404, detail="installer artifact has not been configured")
        record(request, "installer.download", "windows")
        return FileResponse(path, media_type="application/octet-stream", filename="openems-agent.msi")

    @app.post("/api/v1/installers/windows/bundle")
    def installer_bundle(payload: InvitationPayload, request: Request):
        require_writer(request)
        path = artifact()
        parsed = urlsplit(public_base_url or "")
        if path is None or parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise HTTPException(status_code=503, detail="installer artifact and public server URL must be configured")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise HTTPException(status_code=503, detail="public server URL is invalid")
        if parsed.scheme == 'http':
            try:
                loopback = parsed.hostname == 'localhost' or ipaddress.ip_address(parsed.hostname).is_loopback
            except ValueError:
                loopback = False
            if not loopback:
                raise HTTPException(status_code=503, detail="public server URL must use HTTPS")
        if any(character in payload.vdom + public_base_url for character in '\r\n"'):
            raise HTTPException(status_code=422, detail="installation values contain unsupported characters")
        # The script receives data via literal strings, never executable text from request fields.
        def literal(value: str) -> str:
            return "'" + value.replace("'", "''") + "'"
        token = service.create_invitation(payload.vdom, payload.max_uses, payload.ttl_seconds)
        script = ("$ErrorActionPreference = 'Stop'\r\n"
                  "$package = Join-Path $PSScriptRoot 'openems-agent.msi'\r\n"
                  f"$server = {literal(public_base_url)}\r\n$invitation = {literal(token)}\r\n"
                  f"$group = {literal(payload.vdom)}\r\n"
                  "# The invitation is secret. Delete this folder after installation.\r\n"
                  "$arguments = @('/i', ('\"' + $package + '\"'), '/qn', '/norestart', "
                  "('SERVER=\"' + $server.Replace('\"','\"\"') + '\"'), "
                  "('INVITATION=\"' + $invitation + '\"'), ('VDOM=\"' + $group.Replace('\"','\"\"') + '\"'))\r\n"
                  "$process = Start-Process -FilePath msiexec.exe -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden\r\n"
                  "if ($process.ExitCode -notin @(0,3010)) { throw ('Installation failed: ' + $process.ExitCode) }\r\n")
        output = io.BytesIO()
        try:
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as bundle:
                bundle.write(path, "openems-agent.msi")
                bundle.writestr("install.ps1", script.encode("utf-8-sig"))
                bundle.writestr("README.txt", "Run install.ps1 as Administrator. The invitation is secret and limited. Delete this folder after deployment.\n")
        except OSError as error:
            service.revoke_invitation(hashlib.sha256(token.encode()).hexdigest())
            raise HTTPException(status_code=503, detail="installer artifact is unavailable") from error
        record(request, "installer.bundle", "windows", vdom=payload.vdom, max_uses=payload.max_uses, ttl_seconds=payload.ttl_seconds)
        return Response(output.getvalue(), media_type="application/zip", headers={
            "Content-Disposition": 'attachment; filename="openems-windows.zip"', "Cache-Control": "no-store"})
