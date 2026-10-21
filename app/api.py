"""HTTP layer: maps the interoperable endpoints onto EmsService.

Routes mirror SPEC-INTEROP.md:
  endpoint channel : /fct/api/public/v1/register|refresh|update_client_id
  management API   : /api/v1/endpoints/index|count , /api/v1/report/fct/host_tags

Requires FastAPI (see requirements.txt). The core service in service.py has no
web dependency, so unit tests run without installing this layer.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    from fastapi import FastAPI, Form, HTTPException, Request, Response
    from fastapi.responses import JSONResponse, RedirectResponse
    from fastapi.staticfiles import StaticFiles
except ImportError as exc:  # pragma: no cover - only hit without FastAPI
    raise SystemExit(
        "FastAPI is required to run the HTTP server: pip install -r requirements.txt"
    ) from exc

from .audit import AuditEntry, AuditLog, InMemoryAuditLog
from .auth import AdminService

_STATIC_DIR = Path(__file__).parent / "static"


def _actor(request: "Request") -> str:
    claims = getattr(request.state, "admin", None)
    return claims.get("username", "setup") if claims else "setup"

from .models import AssignmentRule, Condition, RegisterRequest
from .saml import SamlError, SamlSp, UnknownIdpError
from .service import (
    EmsService,
    RegistrationError,
    UnknownEndpointError,
    UnknownProfileError,
)


def create_app(
    service: EmsService | None = None,
    saml_sp: SamlSp | None = None,
    record_path: str | None = None,
    admin_service: AdminService | None = None,
    audit_log: AuditLog | None = None,
) -> "FastAPI":
    svc = service or EmsService()
    saml = saml_sp or SamlSp("http://localhost:8013")
    admin = admin_service or AdminService()
    audit = audit_log or InMemoryAuditLog()
    # optional bootstrap admin from env, e.g. OPENEMS_ADMIN=admin:changeme
    env_admin = os.environ.get("OPENEMS_ADMIN")
    if env_admin and ":" in env_admin:
        u, p = env_admin.split(":", 1)
        admin.add_admin(u, p)
    app = FastAPI(title="openems-server", version="0.1.0")

    record_to = record_path or os.environ.get("OPENEMS_RECORD")
    if record_to:
        from .recording import RecorderMiddleware

        app.add_middleware(RecorderMiddleware, out_path=record_to)

    @app.middleware("http")
    async def admin_guard(request: "Request", call_next):
        path = request.url.path
        # Until an admin is created the API runs open (setup mode); once any admin
        # exists, every /api/v1/* call (except login) requires a valid token.
        if admin.has_admins() and path.startswith("/api/v1/") and path != "/api/v1/auth/login":
            header = request.headers.get("authorization", "")
            token = header[7:] if header[:7].lower() == "bearer " else ""
            claims = admin.verify_token(token)
            if claims is None:
                return JSONResponse(
                    {"detail": "authentication required"}, status_code=401
                )
            request.state.admin = claims  # who is acting, for the audit log
        return await call_next(request)

    @app.post("/api/v1/auth/login")
    async def login(payload: dict[str, Any]) -> dict[str, Any]:
        username = str(payload.get("username", ""))
        role = admin.authenticate(username, str(payload.get("password", "")))
        if role is None:
            raise HTTPException(status_code=401, detail="invalid credentials")
        return {"token": admin.issue_token(username, role), "role": role}

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
            "vdom": svc.effective_vdom(endpoint),
            "config_version": svc.current_config_version(svc.effective_vdom(endpoint)),
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

    @app.post("/fct/api/public/v1/host_tags/")
    async def report_host_tags(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            endpoint = svc.ingest_host_tags(
                str(payload.get("client_id", "")), list(payload.get("tags", []))
            )
        except UnknownEndpointError as err:
            raise HTTPException(status_code=404, detail="unknown client_id") from err
        return {"ok": True, "devid": endpoint.devid, "host_tags": endpoint.host_tags}

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
    async def set_profile(vdom: str, payload: dict[str, Any], request: "Request") -> dict[str, Any]:
        profile = svc.set_profile(vdom, payload)
        audit.record(AuditEntry(
            actor=_actor(request), action="profile.publish", target=vdom,
            metadata={"version": profile.version}))
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

    # --- group assignment rules -----------------------------------------

    @app.post("/api/v1/assignment_rules")
    async def add_rule(payload: dict[str, Any], request: "Request") -> dict[str, Any]:
        conditions = [
            Condition(field=c["field"], op=c["op"], value=c["value"])
            for c in payload.get("conditions", [])
        ]
        rule = AssignmentRule(
            id=str(payload.get("id", "")),
            target_vdom=str(payload.get("target_vdom", "")),
            conditions=conditions,
            priority=int(payload.get("priority", 100)),
            enabled=bool(payload.get("enabled", True)),
        )
        svc.add_rule(rule)
        audit.record(AuditEntry(
            actor=_actor(request), action="rule.add", target=rule.id,
            metadata={"target_vdom": rule.target_vdom, "priority": rule.priority}))
        return {"id": rule.id, "target_vdom": rule.target_vdom, "priority": rule.priority}

    @app.get("/api/v1/assignment_rules")
    async def list_rules() -> list[dict[str, Any]]:
        return [
            {
                "id": r.id,
                "target_vdom": r.target_vdom,
                "priority": r.priority,
                "enabled": r.enabled,
                "conditions": [
                    {"field": c.field, "op": c.op, "value": c.value}
                    for c in r.conditions
                ],
            }
            for r in svc.list_rules()
        ]

    @app.delete("/api/v1/assignment_rules/{rule_id}")
    async def delete_rule(rule_id: str, request: "Request") -> dict[str, Any]:
        if not svc.remove_rule(rule_id):
            raise HTTPException(status_code=404, detail="unknown rule")
        audit.record(AuditEntry(
            actor=_actor(request), action="rule.remove", target=rule_id))
        return {"removed": rule_id}

    @app.get("/api/v1/audit")
    async def get_audit(limit: int = 100) -> list[dict[str, Any]]:
        return [
            {"ts": e.ts.isoformat(), "actor": e.actor, "action": e.action,
             "target": e.target, "metadata": e.metadata}
            for e in audit.list(limit)
        ]

    @app.get("/api/v1/endpoints/detail")
    async def endpoint_detail(devid: str) -> dict[str, Any]:
        try:
            e = svc.get_endpoint(devid)
        except UnknownEndpointError as err:
            raise HTTPException(status_code=404, detail="unknown devid") from err
        eff = svc.effective_vdom(e)
        return {
            "devid": e.devid,
            "client_id": e.client_id,
            "hostname": e.hostname,
            "os": e.os,
            "fctver": e.fctver,
            "vdom": e.vdom,
            "effective_vdom": eff,
            "status": e.status.value,
            "host_tags": e.host_tags,
            "config_version": e.config_version,
            "current_config_version": svc.current_config_version(eff),
            "last_seen": e.last_seen.isoformat(),
        }

    @app.get("/api/v1/profiles")
    async def list_profiles() -> list[dict[str, Any]]:
        return [
            {"vdom": p.vdom, "version": p.version, "body": p.body,
             "updated_at": p.updated_at.isoformat()}
            for p in svc.list_profiles()
        ]

    @app.get("/fct/api/public/v1/config/assigned/")
    async def assigned_config(client_id: str) -> dict[str, Any]:
        try:
            profile = svc.effective_profile(client_id)
        except UnknownEndpointError as err:
            raise HTTPException(status_code=404, detail="unknown client_id") from err
        if profile is None:
            raise HTTPException(status_code=404, detail="no profile assigned")
        return {"vdom": profile.vdom, "version": profile.version, "body": profile.body}

    # --- SAML SP (/fct_saml/*) ------------------------------------------

    @app.get("/fct_saml/{prefix}/metadata")
    async def saml_metadata(prefix: str) -> Response:
        return Response(content=saml.metadata(prefix), media_type="application/xml")

    @app.get("/fct_saml/login")
    async def saml_login(prefix: str = "Default", RelayState: str | None = None):
        try:
            url = saml.login_redirect(prefix, relay_state=RelayState)
        except UnknownIdpError as err:
            raise HTTPException(status_code=404, detail="no IdP for prefix") from err
        return RedirectResponse(url, status_code=302)

    @app.post("/fct_saml/{prefix}/acs")
    async def saml_acs(
        prefix: str,
        SAMLResponse: str = Form(...),
        RelayState: str | None = Form(default=None),
    ) -> dict[str, Any]:
        try:
            assertion = saml.consume(prefix, SAMLResponse)
        except UnknownIdpError as err:
            raise HTTPException(status_code=404, detail="no IdP for prefix") from err
        except SamlError as err:
            raise HTTPException(status_code=400, detail=str(err)) from err
        return {
            "name_id": assertion.name_id,
            "attributes": assertion.attributes,
            "relay_state": RelayState,
        }

    @app.post("/fct_saml/parse_remote_metadata")
    async def saml_parse_remote_metadata(payload: dict[str, Any]) -> dict[str, Any]:
        prefix = str(payload.get("prefix", "Default"))
        metadata_xml = str(payload.get("metadata", ""))
        try:
            idp = saml.register_idp_from_metadata(prefix, metadata_xml)
        except SamlError as err:
            raise HTTPException(status_code=400, detail=str(err)) from err
        return {"prefix": prefix, "idp_entity_id": idp.entity_id, "sso_url": idp.sso_url}

    # --- management web console -----------------------------------------

    @app.get("/")
    async def root() -> RedirectResponse:
        return RedirectResponse("/console/", status_code=302)

    if _STATIC_DIR.is_dir():
        app.mount("/console", StaticFiles(directory=_STATIC_DIR, html=True), name="console")

    return app


app = None  # built lazily by `uvicorn app.api:build` or create_app() in code


def build() -> "FastAPI":
    """uvicorn factory wiring backends from env.

    OPENEMS_DATABASE_URL -> Postgres for endpoints/profiles/rules/admins/audit.
    OPENEMS_REDIS_URL    -> Redis for the push queue and SAML replay cache.
    Unset backends fall back to in-memory, so `uvicorn app.api:build` works with
    no infrastructure. OPENEMS_ADMIN / OPENEMS_RECORD are handled in create_app.
    """
    from .service import EmsService

    store = profile_store = rule_store = admin_store = audit_log = None
    queue = replay_cache = None

    dsn = os.environ.get("OPENEMS_DATABASE_URL")
    if dsn:
        from .audit import PostgresAuditLog
        from .stores import (
            PostgresAdminStore,
            PostgresProfileStore,
            PostgresRuleStore,
            PostgresStore,
        )

        store = PostgresStore(dsn); store.init_schema()
        profile_store = PostgresProfileStore(dsn); profile_store.init_schema()
        rule_store = PostgresRuleStore(dsn); rule_store.init_schema()
        admin_store = PostgresAdminStore(dsn); admin_store.init_schema()
        audit_log = PostgresAuditLog(dsn); audit_log.init_schema()

    redis_url = os.environ.get("OPENEMS_REDIS_URL")
    if redis_url:
        from .queue import RedisQueue
        from .replay import RedisReplayCache

        queue = RedisQueue(redis_url)
        replay_cache = RedisReplayCache(redis_url)

    svc = EmsService(
        store=store, queue=queue, profile_store=profile_store, rule_store=rule_store
    )
    admin = AdminService(store=admin_store) if admin_store is not None else AdminService()
    base_url = os.environ.get("OPENEMS_BASE_URL", "http://localhost:8013")
    saml = SamlSp(base_url, replay_cache=replay_cache)
    return create_app(svc, saml_sp=saml, admin_service=admin, audit_log=audit_log)
