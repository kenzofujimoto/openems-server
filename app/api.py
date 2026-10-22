"""Authenticated reference-agent and management HTTP interfaces."""
from __future__ import annotations

import ipaddress
import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, Form, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .audit import AuditEntry, AuditLog, InMemoryAuditLog
from .auth import AdminService, LoginRateLimited
from .limits import RequestSizeLimitMiddleware
from .models import AssignmentRule, Condition, Endpoint, EndpointStatus, RegisterRequest
from .saml import SamlError, SamlSp, UnknownIdpError
from .schemas import (
    AckPayload,
    ClientPayload,
    DevicePayload,
    IdpPayload,
    InvitationPayload,
    LoginPayload,
    RegisterPayload,
    RulePayload,
    TagsPayload,
    profile_response,
)
from .service import (
    EmsService,
    RegistrationError,
    UnknownEndpointError,
    UnknownProfileError,
)

_STATIC_DIR = Path(__file__).parent / 'static'
_COOKIE = 'openems_session'
_SAFE_METHODS = {'GET', 'HEAD', 'OPTIONS'}


def _actor(request: Request) -> str:
    return getattr(request.state, 'admin', {}).get('username', 'setup')


def _loopback(host: str | None) -> bool:
    if host in {'localhost', 'testclient', 'testserver'}:
        return True
    try:
        return ipaddress.ip_address(host or '').is_loopback
    except ValueError:
        return False


def _bearer(request: Request) -> str:
    header = request.headers.get('authorization', '')
    return header[7:] if header[:7].lower() == 'bearer ' else ''


def create_app(service: EmsService | None = None, saml_sp: SamlSp | None = None,
               record_path: str | None = None, admin_service: AdminService | None = None,
               audit_log: AuditLog | None = None, *, lab_mode: bool = False,
               close_resources: list[Any] | None = None) -> FastAPI:
    svc = service or EmsService(require_invitation=not lab_mode)
    saml = saml_sp or SamlSp('http://localhost:8013')
    admin = admin_service or AdminService()
    audit = audit_log or InMemoryAuditLog()
    env_admin = os.environ.get('OPENEMS_ADMIN')
    if env_admin and not admin.has_admins():
        if ':' not in env_admin:
            raise ValueError('OPENEMS_ADMIN must contain username:password')
        username, password = env_admin.split(':', 1)
        admin.add_admin(username, password)

    @asynccontextmanager
    async def lifespan(application):
        yield
        for resource in close_resources or []:
            close = getattr(resource, 'close', None)
            if close:
                close()

    app = FastAPI(title='openems-server', version='0.2.0', lifespan=lifespan)
    app.state.service = svc
    app.state.admin = admin
    app.state.saml = saml

    def record(request: Request, action: str, target: str = '', **metadata) -> None:
        audit.record(AuditEntry(actor=_actor(request), action=action, target=target, metadata=metadata))

    def endpoint_view(endpoint: Endpoint) -> dict[str, Any]:
        assigned = svc.effective_vdom(endpoint)
        desired = svc.effective_profile(endpoint.client_id)
        return {
            'devid': endpoint.devid, 'client_id': endpoint.client_id, 'hostname': endpoint.hostname,
            'os': endpoint.os, 'fctver': endpoint.fctver, 'vdom': endpoint.vdom,
            'effective_vdom': assigned, 'status': endpoint.status.value,
            'online': endpoint.status is EndpointStatus.REGISTERED and
                      (datetime.now(UTC) - endpoint.last_seen).total_seconds() <= 90,
            'host_tags': endpoint.host_tags, 'config_version': endpoint.config_version,
            'current_config_version': desired.version if desired else 0,
            'applied_vdom': endpoint.applied_vdom, 'applied_digest': endpoint.applied_digest,
            'last_error': endpoint.last_error, 'last_applied': endpoint.last_applied.isoformat() if endpoint.last_applied else None,
            'last_seen': endpoint.last_seen.isoformat(),
            'desired_profile': {'vdom': desired.vdom, 'version': desired.version, 'digest': desired.digest} if desired else None,
        }

    @app.middleware('http')
    async def security_guard(request: Request, call_next):
        # Hardening headers apply to every response, including early rejections.
        response = await authorize(request, call_next)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        if request.url.path.startswith(('/api/', '/fct/api/', '/fct_saml/')):
            response.headers['Cache-Control'] = 'no-store'
        return response

    async def authorize(request: Request, call_next):
        path = request.url.path
        local_lab = lab_mode and _loopback(request.client.host if request.client else None)
        if lab_mode and not local_lab:
            return JSONResponse({'detail': 'laboratory mode requires a loopback client'}, status_code=403)
        management = path.startswith('/api/v1/') or path == '/fct_saml/parse_remote_metadata'
        if management and path != '/api/v1/auth/login':
            token = _bearer(request) or request.cookies.get(_COOKIE, '')
            claims = admin.verify_token(token)
            if claims is None and not (local_lab and not admin.has_admins()):
                return JSONResponse({'detail': 'authentication required'}, status_code=401)
            if claims is not None:
                request.state.admin = claims
                request.state.token = token
                action = 'manage_idp' if path == '/fct_saml/parse_remote_metadata' else ('read' if request.method in _SAFE_METHODS else 'write')
                if path == '/api/v1/auth/logout':
                    action = 'read'
                if not admin.is_allowed(claims['role'], action):
                    return JSONResponse({'detail': 'insufficient permission'}, status_code=403)
                cookie_write = request.method not in _SAFE_METHODS and not _bearer(request)
                if cookie_write and not admin.verify_csrf(token, request.headers.get('x-csrf-token', '')):
                    return JSONResponse({'detail': 'invalid CSRF token'}, status_code=403)
        if path.startswith('/fct/api/') and path != '/fct/api/public/v1/register/' and not local_lab:
            client_id = request.query_params.get('client_id', '')
            if request.method not in _SAFE_METHODS:
                try:
                    payload = await request.json()
                    client_id = payload.get('client_id', '') if isinstance(payload, dict) else ''
                except (ValueError, UnicodeError):
                    client_id = ''
            if not isinstance(client_id, str) or not svc.authenticate_device(client_id, _bearer(request)):
                return JSONResponse({'detail': 'device authentication required'}, status_code=401)
            request.state.device = client_id
        return await call_next(request)

    record_to = record_path or os.environ.get('OPENEMS_RECORD')
    if record_to:
        from .recording import RecorderMiddleware
        app.add_middleware(RecorderMiddleware, out_path=record_to)
    app.add_middleware(RequestSizeLimitMiddleware)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, error: RequestValidationError):
        # Never echo submitted values: they may carry passwords or device secrets.
        errors = [{'loc': list(item.get('loc', ())), 'msg': item.get('msg', ''), 'type': item.get('type', '')}
                  for item in error.errors()]
        return JSONResponse({'detail': errors}, status_code=422)

    @app.exception_handler(UnknownEndpointError)
    async def unknown_endpoint(request: Request, error: UnknownEndpointError):
        return JSONResponse({'detail': 'unknown endpoint'}, status_code=404)

    @app.post('/api/v1/auth/login')
    def login(payload: LoginPayload, request: Request, response: Response):
        try:
            role = admin.authenticate_with_rate_limit(payload.username, payload.password,
                                                     request.client.host if request.client else '')
        except LoginRateLimited as error:
            audit.record(AuditEntry(actor=payload.username, action='auth.rate_limited'))
            raise HTTPException(status_code=429, detail='too many login attempts', headers={'Retry-After': str(error.retry_after)}) from error
        if role is None:
            audit.record(AuditEntry(actor=payload.username, action='auth.failure'))
            raise HTTPException(status_code=401, detail='invalid credentials')
        try:
            session = admin.issue_session(payload.username, role)
        except ValueError as error:
            raise HTTPException(status_code=503, detail='session capacity reached') from error
        response.set_cookie(_COOKIE, session['token'], httponly=True, secure=not lab_mode,
                            samesite='strict', max_age=3600, path='/')
        response.headers['Cache-Control'] = 'no-store'
        audit.record(AuditEntry(actor=payload.username, action='auth.login'))
        return {**session, 'username': payload.username, 'role': role}

    @app.get('/api/v1/auth/session')
    def session(request: Request):
        claims = getattr(request.state, 'admin', None)
        if claims is None:
            raise HTTPException(status_code=401, detail='authentication required')
        return {**claims, 'csrf_token': admin.csrf_for_token(request.state.token)}

    @app.post('/api/v1/auth/logout')
    def logout(request: Request, response: Response):
        admin.revoke_token(getattr(request.state, 'token', ''))
        response.delete_cookie(_COOKIE, path='/', httponly=True, secure=not lab_mode, samesite='strict')
        record(request, 'auth.logout')
        return {'ok': True}

    @app.post('/fct/api/public/v1/register/')
    def register(payload: RegisterPayload, request: Request):
        try:
            endpoint = svc.register(RegisterRequest(**payload.model_dump()), reg_ip=request.client.host if request.client else '')
        except RegistrationError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        result = {'client_id': endpoint.client_id, 'emsserial': svc.ems_serial,
                  'status': endpoint.status.value, 'vdom': svc.effective_vdom(endpoint),
                  'config_version': endpoint.config_version}
        if endpoint.device_token:
            result['device_token'] = endpoint.device_token
        return result

    @app.post('/fct/api/public/v1/refresh/')
    def refresh(payload: ClientPayload):
        endpoint = svc.refresh(payload.client_id)
        return {'client_id': endpoint.client_id, 'status': endpoint.status.value}

    @app.post('/fct/api/public/v1/update_client_id/')
    def update_client_id(payload: ClientPayload):
        return {'client_id': svc.update_client_id(payload.client_id).client_id}

    @app.post('/fct/api/public/v1/host_tags/')
    def report_host_tags(payload: TagsPayload):
        endpoint = svc.ingest_host_tags(payload.client_id, payload.tags)
        return {'ok': True, 'devid': endpoint.devid, 'host_tags': endpoint.host_tags}

    @app.get('/api/v1/endpoints/index')
    def endpoints_index():
        return [endpoint_view(endpoint) for endpoint in svc.list_endpoints()]

    @app.get('/api/v1/endpoints/count')
    def endpoints_count():
        return {'count': svc.count()}

    @app.get('/api/v1/endpoints/detail')
    def endpoint_detail(devid: str = Query(max_length=256)):
        return endpoint_view(svc.get_endpoint(devid))

    @app.get('/api/v1/report/fct/host_tags')
    def host_tags(devid: str = Query(max_length=256)):
        return {'devid': devid, 'host_tags': svc.host_tags_by_devid(devid)}

    @app.post('/api/v1/endpoints/credentials/rotate')
    def rotate_credential(payload: DevicePayload, request: Request):
        try:
            token = svc.rotate_device_token(payload.devid)
        except RegistrationError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        record(request, 'device.credential.rotate', payload.devid)
        return {'device_token': token}

    @app.post('/api/v1/endpoints/revoke')
    def revoke_endpoint(payload: DevicePayload, request: Request):
        svc.revoke_device(payload.devid)
        record(request, 'device.revoke', payload.devid)
        return {'ok': True}

    @app.post('/api/v1/enrollment/invitations')
    def invitation(payload: InvitationPayload, request: Request):
        token = svc.create_invitation(payload.vdom, payload.max_uses, payload.ttl_seconds)
        record(request, 'enrollment.invitation.create', payload.vdom, max_uses=payload.max_uses, ttl_seconds=payload.ttl_seconds)
        return {'invitation': token, 'vdom': payload.vdom, 'max_uses': payload.max_uses, 'ttl_seconds': payload.ttl_seconds}

    @app.post('/api/v1/profiles/{vdom}')
    def set_profile(vdom: str, payload: dict[str, Any], request: Request):
        if not vdom or len(vdom) > 128:
            raise HTTPException(status_code=422, detail='invalid group')
        try:
            profile = svc.set_profile(vdom, payload)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        record(request, 'profile.publish', vdom, version=profile.version)
        return {'vdom': profile.vdom, 'version': profile.version, 'digest': profile.digest}

    @app.get('/api/v1/profiles')
    def list_profiles():
        return [{**profile_response(profile), 'updated_at': profile.updated_at.isoformat()} for profile in svc.list_profiles()]

    @app.get('/fct/api/public/v1/config/')
    def get_config(request: Request, vdom: str = 'Default', client_id: str = ''):
        if not lab_mode:
            endpoint = svc.get_endpoint_by_client_id(client_id)
            if svc.effective_vdom(endpoint) != vdom:
                raise HTTPException(status_code=403, detail='policy is not assigned to this device')
        try:
            return profile_response(svc.get_profile(vdom))
        except UnknownProfileError as error:
            raise HTTPException(status_code=404, detail='no profile for group') from error

    @app.get('/fct/api/public/v1/config/assigned/')
    def assigned_config(client_id: str):
        profile = svc.effective_profile(client_id)
        if profile is None:
            endpoint = svc.get_endpoint_by_client_id(client_id)
            return {'vdom': svc.effective_vdom(endpoint), 'version': 0, 'digest': '', 'body': None, 'unassigned': True}
        return profile_response(profile)

    @app.post('/fct/api/public/v1/messages/pull/')
    def pull_messages(payload: ClientPayload):
        return {'messages': svc.pull_messages(payload.client_id)}

    @app.post('/fct/api/public/v1/config/ack/')
    def ack_config(payload: AckPayload):
        if not lab_mode and (payload.vdom is None or payload.digest is None):
            raise HTTPException(status_code=422, detail='policy group and digest are required')
        try:
            endpoint = svc.ack_config(payload.client_id, payload.version, vdom=payload.vdom,
                                      digest=payload.digest, success=payload.success, error=payload.error)
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        return {'client_id': endpoint.client_id, 'config_version': endpoint.config_version,
                'applied_vdom': endpoint.applied_vdom, 'last_error': endpoint.last_error}

    @app.post('/api/v1/assignment_rules')
    def add_rule(payload: RulePayload, request: Request):
        rule = AssignmentRule(id=payload.id, target_vdom=payload.target_vdom,
                              priority=payload.priority, enabled=payload.enabled,
                              conditions=[Condition(**condition.model_dump()) for condition in payload.conditions])
        svc.add_rule(rule)
        record(request, 'rule.add', rule.id, target_vdom=rule.target_vdom, priority=rule.priority)
        return {'id': rule.id, 'target_vdom': rule.target_vdom, 'priority': rule.priority}

    @app.get('/api/v1/assignment_rules')
    def list_rules():
        return [{'id': rule.id, 'target_vdom': rule.target_vdom, 'priority': rule.priority,
                 'enabled': rule.enabled, 'conditions': [{'field': condition.field, 'op': condition.op, 'value': condition.value} for condition in rule.conditions]}
                for rule in svc.list_rules()]

    @app.delete('/api/v1/assignment_rules/{rule_id}')
    def delete_rule(rule_id: str, request: Request):
        if not svc.remove_rule(rule_id):
            raise HTTPException(status_code=404, detail='unknown rule')
        record(request, 'rule.remove', rule_id)
        return {'removed': rule_id}

    @app.get('/api/v1/audit')
    def get_audit(limit: int = Query(default=100, ge=1, le=1000)):
        return [{'ts': entry.ts.isoformat(), 'actor': entry.actor, 'action': entry.action,
                 'target': entry.target, 'metadata': entry.metadata} for entry in audit.list(limit)]

    @app.get('/fct_saml/{prefix}/metadata')
    def saml_metadata(prefix: str):
        return Response(content=saml.metadata(prefix), media_type='application/xml')

    @app.get('/fct_saml/login')
    def saml_login(prefix: str = 'Default', RelayState: str | None = None):
        try:
            return RedirectResponse(saml.login_redirect(prefix, relay_state=RelayState), status_code=302)
        except UnknownIdpError as error:
            raise HTTPException(status_code=404, detail='no IdP for prefix') from error
        except SamlError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.post('/fct_saml/{prefix}/acs')
    def saml_acs(prefix: str, SAMLResponse: str = Form(...), RelayState: str | None = Form(default=None)):
        try:
            assertion = saml.consume(prefix, SAMLResponse, relay_state=RelayState)
        except UnknownIdpError as error:
            raise HTTPException(status_code=404, detail='no IdP for prefix') from error
        except SamlError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        return {'name_id': assertion.name_id, 'attributes': assertion.attributes, 'relay_state': RelayState}

    @app.post('/fct_saml/parse_remote_metadata')
    def saml_parse_remote_metadata(payload: IdpPayload, request: Request):
        try:
            idp = saml.register_idp_from_metadata(payload.prefix, payload.metadata)
        except SamlError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        record(request, 'idp.configure', payload.prefix, entity_id=idp.entity_id)
        return {'prefix': payload.prefix, 'idp_entity_id': idp.entity_id, 'sso_url': idp.sso_url}

    @app.get('/')
    def root():
        return RedirectResponse('/console/', status_code=302)

    app.mount('/console', StaticFiles(directory=_STATIC_DIR, html=True), name='console')
    return app


app = None


def build() -> FastAPI:
    """Wire persistent stores from environment; default HTTP behavior is closed."""
    from .audit import PostgresAuditLog
    from .enrollment import PostgresEnrollmentStore
    from .idp_store import PostgresIdpStore
    from .queue import RedisQueue
    from .replay import RedisPendingRequestStore, RedisReplayCache
    from .sessions import PostgresSessionStore
    from .stores import (
        PostgresAdminStore,
        PostgresProfileStore,
        PostgresRuleStore,
        PostgresStore,
    )

    lab_mode = os.environ.get('OPENEMS_LAB_MODE', '').lower() in {'1', 'true', 'yes'}
    dsn = os.environ.get('OPENEMS_DATABASE_URL')
    secret = os.environ.get('OPENEMS_SESSION_SECRET')
    if dsn and (not secret or len(secret) < 32):
        raise ValueError('OPENEMS_SESSION_SECRET with at least 32 characters is required with PostgreSQL')
    base_url = os.environ.get('OPENEMS_BASE_URL', 'http://localhost:8013')
    parsed = urlsplit(base_url)
    if not parsed.hostname or parsed.scheme not in {'http', 'https'} or parsed.username or parsed.password:
        raise ValueError('OPENEMS_BASE_URL must be an absolute HTTP(S) URL without credentials')
    if parsed.scheme != 'https' and not _loopback(parsed.hostname):
        raise ValueError('OPENEMS_BASE_URL must use HTTPS outside loopback')
    resources = []
    store = profile_store = rule_store = admin_store = audit_log = enrollment_store = idp_store = session_store = None
    if dsn:
        store = PostgresStore(dsn)
        profile_store = PostgresProfileStore(dsn)
        rule_store = PostgresRuleStore(dsn)
        admin_store = PostgresAdminStore(dsn)
        audit_log = PostgresAuditLog(dsn)
        enrollment_store = PostgresEnrollmentStore(dsn)
        idp_store = PostgresIdpStore(dsn)
        session_store = PostgresSessionStore(dsn)
        resources = [store, profile_store, rule_store, admin_store, audit_log, enrollment_store, idp_store, session_store]
        for resource in resources:
            resource.init_schema()
    redis_url = os.environ.get('OPENEMS_REDIS_URL')
    queue = RedisQueue(redis_url) if redis_url else None
    replay = RedisReplayCache(redis_url) if redis_url else None
    pending = RedisPendingRequestStore(redis_url) if redis_url else None
    svc = EmsService(store=store, queue=queue, profile_store=profile_store, rule_store=rule_store,
                     enrollment_store=enrollment_store, require_invitation=not lab_mode)
    enrollment_token = os.environ.get('OPENEMS_ENROLLMENT_TOKEN')
    if enrollment_token:
        from datetime import timedelta
        if len(enrollment_token) < 32:
            raise ValueError('OPENEMS_ENROLLMENT_TOKEN must contain at least 32 characters')
        svc._enrollment.add(enrollment_token, os.environ.get('OPENEMS_ENROLLMENT_VDOM', 'Default'),
                            int(os.environ.get('OPENEMS_ENROLLMENT_USES', '1')),
                            datetime.now(UTC) + timedelta(days=1))
    admin = AdminService(secret=secret, store=admin_store, session_store=session_store)
    saml = SamlSp(base_url, replay_cache=replay, pending_store=pending, idp_store=idp_store)
    if queue:
        resources.append(queue)
    return create_app(svc, saml_sp=saml, admin_service=admin, audit_log=audit_log,
                      lab_mode=lab_mode, close_resources=resources)
