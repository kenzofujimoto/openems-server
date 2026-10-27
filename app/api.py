"""Authenticated reference-agent and management HTTP interfaces."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, Form, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

from agent.policy import CATEGORIES
from agent.uninstall import master_key_from_text

from .audit import AuditEntry, AuditLog, InMemoryAuditLog
from .auth import AdminService, LoginRateLimited
from .capabilities import missing_tags, required_tags
from .categories import CategoryRepository, missing_category_health
from .events import (
    DEFAULT_RETENTION_DAYS,
    BlockEvent,
    EventStore,
    InMemoryEventStore,
    TamperEvent,
    current_hour,
    parse_row,
    parse_tamper,
    validate_retention,
)
from .inventory import InMemoryInventoryStore, InventoryStore
from .limits import RequestSizeLimitMiddleware
from .models import AssignmentRule, Condition, Endpoint, EndpointStatus, RegisterRequest
from .saml import SamlError, SamlSp, UnknownIdpError
from .schemas import (
    AckPayload,
    ClientPayload,
    ControlEventsPayload,
    DeliveryProofPayload,
    DevicePayload,
    EventsPayload,
    IdpPayload,
    InventoryPayload,
    InvitationPayload,
    LocationPolicyPayload,
    LoginPayload,
    NetworkLocationPayload,
    RegisterPayload,
    ReleasePayload,
    RulePayload,
    TagsPayload,
    TamperPayload,
    profile_response,
)
from .service import (
    EmsService,
    RegistrationError,
    UnknownEndpointError,
    UnknownProfileError,
)
from .stores import ProfilePreconditionError
from .uninstall_codes import (
    SecretAlreadyDeliveredError,
    UninstallCodes,
    UninstallDisabledError,
    UninstallStore,
)

_PANEL_DIR = Path(__file__).parent / 'panel_dist'
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
               close_resources: list[Any] | None = None, panel_dir: Path | None = None,
               category_dir: Path | None = None, event_store: EventStore | None = None,
               event_retention_days: int = DEFAULT_RETENTION_DAYS, uninstall_master_key: bytes | None = None,
               uninstall_store: UninstallStore | None = None, inventory_store: InventoryStore | None = None,
               installer_path: Path | None = None, public_base_url: str | None = None) -> FastAPI:
    svc = service or EmsService(require_invitation=not lab_mode)
    saml = saml_sp or SamlSp('http://localhost:8013')
    admin = admin_service or AdminService()
    audit = audit_log or InMemoryAuditLog()
    events = event_store or InMemoryEventStore()
    inventory = inventory_store or InMemoryInventoryStore()
    retention_days = validate_retention(event_retention_days)
    uninstall = UninstallCodes(svc, uninstall_store, uninstall_master_key)
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

    # Block log reads are audited once per admin, route and hour: the panel polls every few seconds.
    audited_views: set[tuple[str, str, datetime]] = set()

    def record_view(request: Request) -> None:
        hour = current_hour()
        key = (_actor(request), request.url.path, hour)
        if key in audited_views:
            return
        audited_views.difference_update({seen for seen in audited_views if seen[2] != hour})
        audited_views.add(key)
        record(request, 'events.read', request.url.path)

    def event_view(event: BlockEvent) -> dict[str, Any]:
        identity = f'{event.devid}|{event.hour.isoformat()}|{event.domain}|{event.reason}|{event.category}|{event.action}|{event.source}'
        category = event.category or None
        return {
            'id': hashlib.sha256(identity.encode('utf-8')).hexdigest()[:16], 'at': event.hour.isoformat(),
            'devid': event.devid, 'kind': 'web_monitor' if event.action == 'monitored' else 'web_block',
            'detail': event.domain if event.reason != 'dropped' else 'eventos não registrados pelo limite do agente',
            'reason': event.reason, 'category': category,
            'category_label': CATEGORIES[category]['label'] if category in CATEGORIES else None, 'count': event.count,
            'action': event.action, 'source': event.source,
        }

    def tamper_view(event: TamperEvent) -> dict[str, Any]:
        identity = f'tamper|{event.devid}|{event.at.isoformat()}|{event.kind}'
        return {'id': hashlib.sha256(identity.encode('utf-8')).hexdigest()[:16], 'at': event.at.isoformat(),
                'devid': event.devid, 'kind': 'tamper', 'detail': event.detail, 'reason': event.kind,
                'category': None, 'category_label': None}

    def endpoint_view(endpoint: Endpoint) -> dict[str, Any]:
        assigned = svc.effective_vdom(endpoint)
        desired = svc.desired_profile(endpoint)
        location_name = next((location['name'] for location in svc.list_locations()
                              if location['id'] == endpoint.location), '')
        return {
            'devid': endpoint.devid, 'client_id': endpoint.client_id, 'hostname': endpoint.hostname,
            'os': endpoint.os, 'fctver': endpoint.fctver, 'vdom': endpoint.vdom,
            'effective_vdom': assigned, 'status': endpoint.status.value,
            'online': endpoint.status is EndpointStatus.REGISTERED and
                      (datetime.now(UTC) - endpoint.last_seen).total_seconds() <= 90,
            'host_tags': endpoint.host_tags, 'config_version': endpoint.config_version,
            'current_config_version': desired.version if desired else 0,
            'applied_vdom': endpoint.applied_vdom, 'applied_digest': endpoint.applied_digest,
            'location': endpoint.location, 'location_name': location_name,
            'last_error': endpoint.last_error, 'last_applied': endpoint.last_applied.isoformat() if endpoint.last_applied else None,
            'last_seen': endpoint.last_seen.isoformat(),
            'desired_profile': {'vdom': desired.vdom, 'version': desired.version, 'digest': desired.digest} if desired else None,
            'missing_capabilities': missing_tags(desired.body, endpoint.host_tags) if desired else [],
        }

    def purge_personal_data() -> None:
        before = datetime.now(UTC) - timedelta(days=retention_days)
        events.purge(current_hour(before))
        events.purge_tamper(before)
        inventory.purge(before)

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

    @app.exception_handler(UninstallDisabledError)
    async def uninstall_disabled(request: Request, error: UninstallDisabledError):
        return JSONResponse({'detail': 'uninstall codes are not configured on this server'}, status_code=503)

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

    categories = CategoryRepository(category_dir) if category_dir else None

    # Device routes: the middleware has already checked client_id and the device token.
    @app.get('/fct/api/public/v1/categories/')
    def category_manifest():
        return categories.manifest() if categories else {'version': None, 'attribution': '', 'categories': []}

    @app.get('/fct/api/public/v1/categories/file/')
    def category_file(id: str = Query(max_length=32), digest: str = Query(pattern=r'^[0-9a-f]{64}$')):
        data = categories.file(id, digest) if categories else None
        if data is None:
            raise HTTPException(status_code=404, detail='category file not published')
        return Response(content=data, media_type='application/octet-stream')

    @app.post('/fct/api/public/v1/events/')
    def report_events(payload: EventsPayload):
        # Rows that cannot be stored are skipped, not refused: a retried batch would fail forever.
        devid = svc.get_endpoint_by_client_id(payload.client_id).devid
        now = datetime.now(UTC)
        events.purge(current_hour(now) - timedelta(days=retention_days))
        accepted = [event for row in payload.events
                    if (event := parse_row(devid, row, now=now, retention_days=retention_days)) is not None]
        if payload.dropped:
            dropped_row = BlockEvent(devid=devid, hour=current_hour(now), domain='', reason='dropped',
                                          category='', count=payload.dropped)
            stored = [*accepted, dropped_row]
        else:
            stored = accepted
        result = {'accepted': len(accepted), 'rejected': len(payload.events) - len(accepted)}
        if payload.batch_id is not None:
            fingerprint = hashlib.sha256(json.dumps(
                {'events': [row.model_dump() for row in payload.events], 'dropped': payload.dropped},
                sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')).hexdigest()
            try:
                result['duplicate'] = not events.add_batch(devid, payload.batch_id, stored, fingerprint)
            except ValueError as error:
                raise HTTPException(status_code=409, detail=str(error)) from error
            except OverflowError as error:
                raise HTTPException(status_code=429, detail=str(error)) from error
        else:
            events.add(stored)
        return result

    @app.post('/fct/api/public/v1/tamper/')
    def report_tamper(payload: TamperPayload):
        devid = svc.get_endpoint_by_client_id(payload.client_id).devid
        now = datetime.now(UTC)
        events.purge_tamper(now - timedelta(days=retention_days))
        accepted = [event for row in payload.events
                    if (event := parse_tamper(devid, row, now=now, retention_days=retention_days)) is not None]
        if payload.dropped:
            accepted.append(TamperEvent(devid=devid, at=now.replace(microsecond=0), kind='dropped',
                                        detail=f'{payload.dropped} tamper events not recorded by the agent limit'))
        events.add_tamper(accepted)
        return {'accepted': len(accepted) - (1 if payload.dropped else 0),
                'rejected': len(payload.events) - len(accepted) + (1 if payload.dropped else 0)}

    @app.post('/fct/api/public/v1/uninstall_secret/')
    def uninstall_secret(payload: ClientPayload):
        try:
            secret = uninstall.deliver_secret(payload.client_id)
        except SecretAlreadyDeliveredError as error:
            raise HTTPException(status_code=409, detail='uninstall secret already delivered') from error
        return {'secret': secret.hex()}

    @app.post('/fct/api/public/v1/uninstall_secret/ack/')
    def uninstall_secret_ack(payload: DeliveryProofPayload):
        if not uninstall.confirm_delivery(payload.client_id, payload.proof):
            raise HTTPException(status_code=403, detail='delivery proof does not match')
        return {'ok': True}

    @app.post('/fct/api/public/v1/host_tags/')
    def report_host_tags(payload: TagsPayload):
        endpoint = svc.ingest_host_tags(payload.client_id, payload.tags)
        return {'ok': True, 'devid': endpoint.devid, 'host_tags': endpoint.host_tags}

    @app.post('/fct/api/public/v1/inventory/')
    def report_inventory(payload: InventoryPayload):
        endpoint = svc.get_endpoint_by_client_id(payload.client_id)
        collected = datetime.fromisoformat(payload.collected_at)
        now = datetime.now(UTC)
        if not now - timedelta(days=retention_days) <= collected <= now + timedelta(hours=1):
            raise HTTPException(status_code=422, detail='inventory timestamp is outside the retention window')
        purge_personal_data()
        snapshot = payload.model_dump(by_alias=True, exclude={'client_id'})
        snapshot['devid'] = endpoint.devid
        if not inventory.replace(snapshot):
            raise HTTPException(status_code=409, detail='a newer inventory snapshot is already stored')
        return {'accepted': True}

    @app.get('/api/v1/endpoints/inventory')
    def endpoint_inventory(request: Request, devid: str = Query(min_length=1, max_length=256)):
        svc.get_endpoint(devid)
        purge_personal_data()
        record(request, 'inventory.read', devid)
        return inventory.snapshot(devid) or {'devid': devid, 'collected_at': None, 'applications': [], 'usb_devices': []}

    @app.post('/fct/api/public/v1/control_events/')
    def report_control_events(payload: ControlEventsPayload):
        devid = svc.get_endpoint_by_client_id(payload.client_id).devid
        now = datetime.now(UTC)
        purge_personal_data()
        accepted = []
        for row in payload.events:
            try:
                at = datetime.fromisoformat(row.at)
            except ValueError:
                continue
            if at.tzinfo is None or not now - timedelta(days=retention_days) <= at <= now + timedelta(hours=1):
                continue
            accepted.append({**row.model_dump(), 'at': at.astimezone(UTC).isoformat(), 'devid': devid})
        inventory.add_events(accepted)
        if payload.dropped:
            audit.record(AuditEntry(actor='device', action='controls.dropped', target=devid,
                                    metadata={'count': payload.dropped}))
        return {'accepted': len(accepted), 'rejected': len(payload.events) - len(accepted)}

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

    @app.post('/api/v1/endpoints/uninstall_code')
    def uninstall_code(payload: DevicePayload, request: Request):
        counter, value = uninstall.next_code(payload.devid)
        # The code itself is never recorded: whoever reads the audit log must not be able to use it.
        record(request, 'endpoint.uninstall_code', payload.devid, counter=counter)
        return {'devid': payload.devid, 'counter': counter, 'code': value}

    @app.post('/api/v1/endpoints/uninstall_secret/reset')
    def reopen_uninstall_secret(payload: DevicePayload, request: Request):
        uninstall.reopen_delivery(payload.devid)
        record(request, 'endpoint.uninstall_secret.reset', payload.devid)
        return {'ok': True}

    @app.get('/api/v1/uninstall_release')
    def list_uninstall_releases():
        return [{'scope': release.scope, 'released_at': release.released_at.isoformat(),
                 'released_by': release.released_by} for release in uninstall.releases()]

    @app.post('/api/v1/uninstall_release')
    def set_uninstall_release(payload: ReleasePayload, request: Request):
        uninstall.set_release(payload.scope, payload.released, _actor(request))
        record(request, 'uninstall.release' if payload.released else 'uninstall.release.revoke', payload.scope)
        return {'scope': payload.scope, 'released': payload.released}

    @app.post('/api/v1/enrollment/invitations')
    def invitation(payload: InvitationPayload, request: Request):
        token = svc.create_invitation(payload.vdom, payload.max_uses, payload.ttl_seconds)
        record(request, 'enrollment.invitation.create', payload.vdom, max_uses=payload.max_uses, ttl_seconds=payload.ttl_seconds)
        return {'invitation': token, 'vdom': payload.vdom, 'max_uses': payload.max_uses, 'ttl_seconds': payload.ttl_seconds}

    @app.post('/api/v1/profiles/{vdom}')
    def set_profile(vdom: str, payload: dict[str, Any], request: Request):
        if not vdom or len(vdom) > 128:
            raise HTTPException(status_code=422, detail='invalid group')
        expected_digest = request.headers.get('if-match')
        if expected_digest is not None:
            expected_digest = expected_digest.strip('"')
            if not re.fullmatch(r'[a-f0-9]{64}', expected_digest):
                raise HTTPException(status_code=422, detail='If-Match must contain the current policy digest')
        try:
            profile = svc.set_profile(vdom, payload, expected_digest)
        except ProfilePreconditionError as error:
            raise HTTPException(status_code=412, detail='profile changed; reload before publishing') from error
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        record(request, 'profile.publish', vdom, version=profile.version)
        warnings = [{'devid': endpoint.devid, 'missing': missing}
                    for endpoint in sorted(svc.list_endpoints(), key=lambda item: item.devid)
                    if endpoint.status is EndpointStatus.REGISTERED and svc.effective_vdom(endpoint) == vdom
                    and (missing := missing_tags(profile.body, endpoint.host_tags))]
        return {'vdom': profile.vdom, 'version': profile.version, 'digest': profile.digest, 'warnings': warnings}

    @app.get('/api/v1/profiles')
    def list_profiles():
        return [{**profile_response(profile), 'updated_at': profile.updated_at.isoformat()} for profile in svc.list_profiles()]

    @app.get('/api/v1/network_locations')
    def list_network_locations():
        return svc.list_locations()

    @app.post('/api/v1/network_locations')
    def create_network_location(payload: NetworkLocationPayload, request: Request):
        location = payload.model_dump()
        if not svc.create_location(location):
            raise HTTPException(status_code=409, detail='location already exists')
        record(request, 'network_location.create', payload.id)
        return location

    @app.put('/api/v1/network_locations/{location_id}')
    def update_network_location(location_id: str, payload: NetworkLocationPayload, request: Request):
        if payload.id != location_id:
            raise HTTPException(status_code=422, detail='location id must match the URL')
        location = payload.model_dump()
        if not svc.update_location(location):
            raise HTTPException(status_code=404, detail='unknown location')
        record(request, 'network_location.update', payload.id)
        return location

    @app.delete('/api/v1/network_locations/{location_id}')
    def delete_network_location(location_id: str, request: Request):
        if not svc.remove_location(location_id):
            raise HTTPException(status_code=404, detail='unknown location')
        record(request, 'network_location.delete', location_id)
        return {'ok': True}

    @app.get('/api/v1/location_policies')
    def list_location_policies():
        return svc.list_location_policies()

    @app.post('/api/v1/location_policies')
    def set_location_policy(payload: LocationPolicyPayload, request: Request):
        try:
            svc.set_location_policy(payload.vdom, payload.location_id, payload.inside_vdom)
        except (UnknownProfileError, ValueError) as error:
            raise HTTPException(status_code=404, detail='unknown location or inside profile') from error
        record(request, 'location_policy.set', payload.location_id, vdom=payload.vdom, inside_vdom=payload.inside_vdom)
        return payload.model_dump()

    @app.delete('/api/v1/location_policies')
    def delete_location_policy(request: Request, vdom: str = Query(min_length=1, max_length=128),
                               location_id: str = Query(min_length=1, max_length=128)):
        if not svc.remove_location_policy(vdom, location_id):
            raise HTTPException(status_code=404, detail='unknown location policy')
        record(request, 'location_policy.delete', location_id, vdom=vdom)
        return {'ok': True}

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
    def assigned_config(client_id: str, request: Request):
        endpoint = svc.get_endpoint_by_client_id(client_id)
        profile = svc.effective_profile(client_id)
        if profile is None:
            result = {'vdom': svc.effective_vdom(endpoint), 'version': 0, 'digest': '', 'body': None, 'unassigned': True}
        else:
            result = profile_response(profile)
        result['client_ip'] = request.client.host if request.client else ''
        result['locations'] = svc.assigned_locations(endpoint)
        bodies = [profile.body] if profile is not None else []
        bodies.extend(location['assignment']['body'] for location in result['locations'])
        for body in bodies:
            require_action_capabilities(body, endpoint)
        if (release := uninstall.release_for(endpoint)) is not None:
            result['uninstall_release'] = release
        return result

    def require_action_capabilities(body: Any, endpoint: Endpoint) -> None:
        if 'web-filter:actions' in required_tags(body):
            missing = missing_tags(body, endpoint.host_tags)
            if missing:
                raise HTTPException(status_code=409, detail={
                    'message': 'agent does not support the required web policy actions', 'missing_capabilities': missing,
                })

    @app.post('/fct/api/public/v1/messages/pull/')
    def pull_messages(payload: ClientPayload):
        return {'messages': svc.pull_messages(payload.client_id)}

    @app.post('/fct/api/public/v1/config/ack/')
    def ack_config(payload: AckPayload):
        if not lab_mode and (payload.vdom is None or payload.digest is None):
            raise HTTPException(status_code=422, detail='policy group and digest are required')
        if payload.success:
            endpoint = svc.get_endpoint_by_client_id(payload.client_id)
            profile = svc.effective_profile(payload.client_id)
            body = profile.body if profile is not None else {}
            if payload.location:
                assignment = next((item['assignment'] for item in svc.assigned_locations(endpoint)
                                   if item['id'] == payload.location), None)
                if assignment is not None:
                    body = assignment['body']
            require_action_capabilities(body, endpoint)
        try:
            endpoint = svc.ack_config(payload.client_id, payload.version, vdom=payload.vdom,
                                      digest=payload.digest, success=payload.success, error=payload.error,
                                      location=payload.location)
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        return {'client_id': endpoint.client_id, 'config_version': endpoint.config_version,
                'applied_vdom': endpoint.applied_vdom, 'last_error': endpoint.last_error,
                'location': endpoint.location}

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

    @app.get('/api/v1/events')
    def list_events(request: Request, limit: int = Query(default=50, ge=1, le=1000),
                    action: str | None = Query(default=None, pattern='^(blocked|monitored)$')):
        record_view(request)
        purge_personal_data()
        rows = [(event.hour, event_view(event)) for event in events.recent(limit, action=action)]
        if action is None:
            rows += [(event.at, tamper_view(event)) for event in events.recent_tamper(limit)]
            rows += [(datetime.fromisoformat(event['at']), {
                **event, 'detail': event['target'], 'reason': event['rule_id'], 'category': None, 'category_label': None,
            }) for event in inventory.recent_events(limit)]
        rows.sort(key=lambda row: row[0], reverse=True)
        return [view for _, view in rows[:limit]]

    @app.get('/api/v1/stats/overview')
    def overview(request: Request):
        record_view(request)
        purge_personal_data()
        today = current_hour().replace(hour=0)
        start, previous_start = today - timedelta(days=6), today - timedelta(days=13)
        totals = events.daily_totals(previous_start)
        monitored = events.daily_totals(start, action='monitored')
        dropped = events.daily_totals(start, action='dropped')
        control_totals = inventory.daily_totals(previous_start)
        days = [(start + timedelta(days=offset)).date() for offset in range(7)]
        previous = sum(total for day, total in totals.items() if day < start.date())
        previous += sum(counts['apps'] + counts['usb'] for day, counts in control_totals.items()
                        if day < start.date().isoformat())
        return {
            'generated_at': datetime.now(UTC).isoformat(),
            'blocks_by_day': [{'date': day.isoformat(), 'web': totals.get(day, 0),
                              **control_totals.get(day.isoformat(), {'apps': 0, 'usb': 0})} for day in days],
            'top_domains': [{'domain': domain, 'count': count} for domain, count in events.top_domains(start, 5)],
            'monitoring_by_day': [{'date': day.isoformat(), 'web': monitored.get(day, 0)} for day in days],
            'dropped_by_day': [{'date': day.isoformat(), 'web': dropped.get(day, 0)} for day in days],
            # No history of machine status is kept, so only blocks can be compared.
            'previous_period': {'blocks': previous},
            'retention_days': retention_days,
        }

    @app.get('/api/v1/categories')
    def list_categories():
        health = categories.health() if categories else missing_category_health()
        manifest = categories.manifest() if categories and health['status'] != 'invalid' else {
            'version': None, 'attribution': '', 'categories': [],
        }
        return {'version': manifest.get('version'), 'attribution': manifest.get('attribution', ''),
                'health': health,
                'categories': [{key: entry[key] for key in ('id', 'label', 'group', 'count')}
                               for entry in manifest['categories']]}

    @app.get('/api/v1/audit')
    def get_audit(limit: int = Query(default=100, ge=1, le=1000)):
        return [{'ts': entry.ts.isoformat(), 'actor': entry.actor, 'action': entry.action,
                 'target': entry.target, 'metadata': entry.metadata} for entry in audit.list(limit)]

    from .management import attach_management_routes
    attach_management_routes(app, svc, admin, record, retention_days, installer_path, public_base_url)

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

    panel_root = (panel_dir or _PANEL_DIR).resolve()

    @app.get('/')
    def root():
        return RedirectResponse('/panel/', status_code=302)

    @app.get('/panel', include_in_schema=False)
    def panel_redirect():
        return RedirectResponse('/panel/', status_code=307)

    @app.get('/panel/{path:path}', include_in_schema=False)
    def panel(path: str = ''):
        # Built assets are served as files; every other path is a client route.
        target = (panel_root / path).resolve()
        if path and target.is_relative_to(panel_root) and target.is_file():
            return FileResponse(target)
        index = panel_root / 'index.html'
        if not index.is_file():
            raise HTTPException(status_code=404, detail='panel is not built')
        return FileResponse(index, headers={'Cache-Control': 'no-store'})

    @app.get('/console')
    @app.get('/console/')
    def old_console():
        return RedirectResponse('/panel/', status_code=308)
    return app


app = None


def build() -> FastAPI:
    """Wire persistent stores from environment; default HTTP behavior is closed."""
    from .audit import PostgresAuditLog
    from .enrollment import PostgresEnrollmentStore
    from .events import PostgresEventStore
    from .idp_store import PostgresIdpStore
    from .inventory import PostgresInventoryStore
    from .network_locations import PostgresLocationStore
    from .queue import RedisQueue
    from .replay import RedisPendingRequestStore, RedisReplayCache
    from .sessions import PostgresSessionStore
    from .stores import (
        PostgresAdminStore,
        PostgresProfileStore,
        PostgresRuleStore,
        PostgresStore,
    )
    from .uninstall_codes import PostgresUninstallStore

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
    event_store = uninstall_store = location_store = inventory_store = None
    if dsn:
        store = PostgresStore(dsn)
        profile_store = PostgresProfileStore(dsn)
        rule_store = PostgresRuleStore(dsn)
        admin_store = PostgresAdminStore(dsn)
        audit_log = PostgresAuditLog(dsn)
        enrollment_store = PostgresEnrollmentStore(dsn)
        idp_store = PostgresIdpStore(dsn)
        session_store = PostgresSessionStore(dsn)
        event_store = PostgresEventStore(dsn)
        uninstall_store = PostgresUninstallStore(dsn)
        location_store = PostgresLocationStore(dsn)
        inventory_store = PostgresInventoryStore(dsn)
        resources = [store, profile_store, rule_store, admin_store, audit_log, enrollment_store, idp_store, session_store,
                     event_store, uninstall_store, location_store, inventory_store]
        for resource in resources:
            resource.init_schema()
    redis_url = os.environ.get('OPENEMS_REDIS_URL')
    queue = RedisQueue(redis_url) if redis_url else None
    replay = RedisReplayCache(redis_url) if redis_url else None
    pending = RedisPendingRequestStore(redis_url) if redis_url else None
    svc = EmsService(store=store, queue=queue, profile_store=profile_store, rule_store=rule_store,
                     location_store=location_store,
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
    category_dir = os.environ.get('OPENEMS_CATEGORIES_DIR')
    # Optional: empty (docker-compose default) leaves uninstall codes off and removal unprotected.
    uninstall_key_text = os.environ.get('OPENEMS_UNINSTALL_MASTER_KEY', '')
    uninstall_key = None
    if uninstall_key_text.strip():
        try:
            uninstall_key = master_key_from_text(uninstall_key_text)
        except ValueError as error:
            raise ValueError('OPENEMS_UNINSTALL_MASTER_KEY must contain at least 32 bytes') from error
    retention = os.environ.get('OPENEMS_EVENT_RETENTION_DAYS', str(DEFAULT_RETENTION_DAYS))
    if not retention.isdigit():
        raise ValueError('OPENEMS_EVENT_RETENTION_DAYS must be a whole number of days')
    return create_app(svc, saml_sp=saml, admin_service=admin, audit_log=audit_log,
                      lab_mode=lab_mode, close_resources=resources,
                      category_dir=Path(category_dir) if category_dir else None,
                      event_store=event_store, event_retention_days=int(retention),
                      uninstall_master_key=uninstall_key, uninstall_store=uninstall_store,
                      inventory_store=inventory_store,
                      installer_path=Path(os.environ['OPENEMS_INSTALLER_PATH']) if os.environ.get('OPENEMS_INSTALLER_PATH') else None,
                      public_base_url=base_url)
