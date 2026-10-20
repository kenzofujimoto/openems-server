"""Core endpoint-management service (clean-room reference implementation).

Implements the minimal behaviour of the endpoint channel described in
SPEC-INTEROP.md sections 2 and 3: register, refresh, update_client_id,
host-tag ingestion and endpoint listing. Storage is pluggable; the default is
an in-memory store suitable for tests and a first bring-up.
"""

from __future__ import annotations

import secrets
from datetime import timezone, datetime

from .models import Endpoint, EndpointStatus, RegisterRequest
from .stores import InMemoryStore, Store


class RegistrationError(Exception):
    """Raised when a registration cannot be completed."""


class UnknownEndpointError(Exception):
    """Raised when an operation targets an endpoint that is not registered."""


class EmsService:
    """Interoperable endpoint-management logic.

    `require_invitation` mirrors the observed behaviour where some servers only
    admit endpoints presenting a valid invitation code.
    """

    def __init__(
        self,
        store: Store | None = None,
        *,
        ems_serial: str = "OPENEMS0000000000",
        require_invitation: bool = False,
        valid_invitations: set[str] | None = None,
    ) -> None:
        self._store: Store = store or InMemoryStore()
        self._ems_serial = ems_serial
        self._require_invitation = require_invitation
        self._valid_invitations = valid_invitations or set()

    # --- endpoint channel (port 8013) -----------------------------------

    def register(self, req: RegisterRequest, *, reg_ip: str = "") -> Endpoint:
        if not req.devid:
            raise RegistrationError("devid is required")
        if self._require_invitation:
            if not req.invitation or req.invitation not in self._valid_invitations:
                raise RegistrationError("a valid invitation code is required")

        existing = self._store.get_by_devid(req.devid)
        client_id = existing.client_id if existing else self._new_client_id()

        endpoint = Endpoint(
            devid=req.devid,
            client_id=client_id,
            hostname=req.hostname,
            os=req.os,
            fctver=req.fctver,
            vdom=req.vdom,
            status=EndpointStatus.REGISTERED,
            reg_ip=reg_ip,
            host_tags=existing.host_tags if existing else [],
        )
        self._store.upsert(endpoint)
        return endpoint

    def refresh(self, client_id: str) -> Endpoint:
        endpoint = self._store.get_by_client_id(client_id)
        if endpoint is None:
            raise UnknownEndpointError(client_id)
        endpoint.last_seen = datetime.now(timezone.utc)
        self._store.upsert(endpoint)
        return endpoint

    def update_client_id(self, old_client_id: str) -> Endpoint:
        endpoint = self._store.get_by_client_id(old_client_id)
        if endpoint is None:
            raise UnknownEndpointError(old_client_id)
        endpoint.client_id = self._new_client_id()
        self._store.upsert(endpoint)
        return endpoint

    def ingest_host_tags(self, client_id: str, tags: list[str]) -> Endpoint:
        endpoint = self._store.get_by_client_id(client_id)
        if endpoint is None:
            raise UnknownEndpointError(client_id)
        endpoint.host_tags = list(tags)
        endpoint.last_seen = datetime.now(timezone.utc)
        self._store.upsert(endpoint)
        return endpoint

    # --- management API (/api/v1) ---------------------------------------

    def list_endpoints(self) -> list[Endpoint]:
        return self._store.all()

    def count(self) -> int:
        return len(self._store.all())

    def host_tags_by_devid(self, devid: str) -> list[str]:
        endpoint = self._store.get_by_devid(devid)
        if endpoint is None:
            raise UnknownEndpointError(devid)
        return endpoint.host_tags

    # --- helpers --------------------------------------------------------

    @property
    def ems_serial(self) -> str:
        return self._ems_serial

    @staticmethod
    def _new_client_id() -> str:
        return secrets.token_hex(16)
