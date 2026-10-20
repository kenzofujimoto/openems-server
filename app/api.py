"""HTTP layer: maps the interoperable endpoints onto EmsService.

Routes mirror SPEC-INTEROP.md:
  endpoint channel : /fct/api/public/v1/register|refresh|update_client_id
  management API   : /api/v1/endpoints/index|count , /api/v1/report/fct/host_tags

Requires FastAPI (see requirements.txt). The core service in service.py has no
web dependency, so unit tests run without installing this layer.
"""

from __future__ import annotations

from typing import Any

try:
    from fastapi import FastAPI, HTTPException, Request
except ImportError as exc:  # pragma: no cover - only hit without FastAPI
    raise SystemExit(
        "FastAPI is required to run the HTTP server: pip install -r requirements.txt"
    ) from exc

from .models import RegisterRequest
from .service import (
    EmsService,
    RegistrationError,
    UnknownEndpointError,
    UnknownProfileError,
)


def create_app(service: EmsService | None = None) -> "FastAPI":
    svc = service or EmsService()
    app = FastAPI(title="openems-server", version="0.1.0")

    @app.post("/fct/api/public/v1/register/")
    async def register(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        try:
            endpoint = svc.register(
                RegisterRequest(
                    devid=str(payload.get("devid", "")),
                    fctver=str(payload.get("fctver", "")),
                    os=str(payload.get("os", "")),
                    hostname=str(payload.get("hostname", "")),
                    vdom=str(payload.get("vdom", "Default")),
                    invitation=payload.get("invitation"),
                    key=payload.get("key"),
                ),
                reg_ip=request.client.host if request.client else "",
            )
        except RegistrationError as err:
            raise HTTPException(status_code=400, detail=str(err)) from err
        return {
            "client_id": endpoint.client_id,
            "emsserial": svc.ems_serial,
            "status": endpoint.status.value,
            "config_version": svc.current_config_version(endpoint.vdom),
        }

    @app.post("/fct/api/public/v1/refresh/")
    async def refresh(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            endpoint = svc.refresh(str(payload.get("client_id", "")))
        except UnknownEndpointError as err:
            raise HTTPException(status_code=404, detail="unknown client_id") from err
        return {"client_id": endpoint.client_id, "status": endpoint.status.value}

    @app.post("/fct/api/public/v1/update_client_id/")
    async def update_client_id(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            endpoint = svc.update_client_id(str(payload.get("client_id", "")))
        except UnknownEndpointError as err:
            raise HTTPException(status_code=404, detail="unknown client_id") from err
        return {"client_id": endpoint.client_id}

    @app.get("/api/v1/endpoints/index")
    async def endpoints_index() -> list[dict[str, Any]]:
        return [
            {
                "devid": e.devid,
                "hostname": e.hostname,
                "os": e.os,
                "status": e.status.value,
                "host_tags": e.host_tags,
            }
            for e in svc.list_endpoints()
        ]

    @app.get("/api/v1/endpoints/count")
    async def endpoints_count() -> dict[str, int]:
        return {"count": svc.count()}

    @app.get("/api/v1/report/fct/host_tags")
    async def host_tags(devid: str) -> dict[str, Any]:
        try:
            return {"devid": devid, "host_tags": svc.host_tags_by_devid(devid)}
        except UnknownEndpointError as err:
            raise HTTPException(status_code=404, detail="unknown devid") from err

    # --- config / profile push -----------------------------------------

    @app.post("/api/v1/profiles/{vdom}")
    async def set_profile(vdom: str, payload: dict[str, Any]) -> dict[str, Any]:
        profile = svc.set_profile(vdom, payload)
        return {"vdom": profile.vdom, "version": profile.version}

    @app.get("/fct/api/public/v1/config/")
    async def get_config(vdom: str = "Default") -> dict[str, Any]:
        try:
            profile = svc.get_profile(vdom)
        except UnknownProfileError as err:
            raise HTTPException(status_code=404, detail="no profile for vdom") from err
        return {"vdom": profile.vdom, "version": profile.version, "body": profile.body}

    @app.post("/fct/api/public/v1/messages/pull/")
    async def pull_messages(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            messages = svc.pull_messages(str(payload.get("client_id", "")))
        except UnknownEndpointError as err:
            raise HTTPException(status_code=404, detail="unknown client_id") from err
        return {"messages": messages}

    @app.post("/fct/api/public/v1/config/ack/")
    async def ack_config(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            endpoint = svc.ack_config(
                str(payload.get("client_id", "")), int(payload.get("version", 0))
            )
        except UnknownEndpointError as err:
            raise HTTPException(status_code=404, detail="unknown client_id") from err
        return {"client_id": endpoint.client_id, "config_version": endpoint.config_version}

    return app


app = None  # built lazily by `uvicorn app.api:build` or create_app() in code


def build() -> "FastAPI":
    return create_app()
