"""Core endpoint-management service (clean-room reference implementation).

Implements the minimal behaviour of the endpoint channel described in
SPEC-INTEROP.md sections 2 and 3: register, refresh, update_client_id,
host-tag ingestion and endpoint listing. Storage is pluggable; the default is
an in-memory store suitable for tests and a first bring-up.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import timezone, datetime, timedelta
from threading import RLock

from typing import Any

from .models import AssignmentRule, Endpoint, EndpointStatus, Profile, RegisterRequest
from .enrollment import EnrollmentStore, InMemoryEnrollmentStore
from agent.policy import validate_policy
from .queue import InMemoryQueue, Queue
from .rules import evaluate_rules
from .stores import (
    InMemoryProfileStore,
    InMemoryRuleStore,
    InMemoryStore,
    ProfileStore,
    RuleStore,
    Store,
)


class RegistrationError(Exception):
    """Raised when a registration cannot be completed."""


class UnknownEndpointError(Exception):
    """Raised when an operation targets an endpoint that is not registered."""


class UnknownProfileError(Exception):
    """Raised when a vdom has no profile."""


class EmsService:
    """Interoperable endpoint-management logic.

    `require_invitation` mirrors the observed behaviour where some servers only
    admit endpoints presenting a valid invitation code.
    """

    def __init__(
        self,
        store: Store | None = None,
        *,
        queue: Queue | None = None,
        profile_store: ProfileStore | None = None,
        rule_store: RuleStore | None = None,
        ems_serial: str = "OPENEMS0000000000",
        require_invitation: bool = True,
        valid_invitations: set[str] | None = None,
        enrollment_store: EnrollmentStore | None = None,
    ) -> None:
        self._store: Store = store or InMemoryStore()
        self._queue: Queue = queue or InMemoryQueue()
        self._profile_store: ProfileStore = profile_store or InMemoryProfileStore()
        self._rule_store: RuleStore = rule_store or InMemoryRuleStore()
        self._ems_serial = ems_serial
        self._require_invitation = require_invitation
        self._enrollment = enrollment_store or InMemoryEnrollmentStore()
        self._lock = RLock()
        for invitation in valid_invitations or set():
            self._enrollment.add(invitation, "Default", 1, datetime.now(timezone.utc) + timedelta(days=1))

    # --- endpoint channel (port 8013) -----------------------------------

    def register(self, req: RegisterRequest, *, reg_ip: str = "") -> Endpoint:
        if not req.devid:
            raise RegistrationError("devid is required")
        with self._lock:
            existing = self._store.get_by_devid(req.devid)
            if existing:
                if self._require_invitation and not self.authenticate_device(existing.client_id, req.key or ""):
                    raise RegistrationError("device proof of possession is required")
                if existing.status is EndpointStatus.UNREGISTERED:
                    raise RegistrationError("device is revoked")
                existing.hostname = req.hostname or existing.hostname
                existing.os = req.os or existing.os
                existing.fctver = req.fctver or existing.fctver
                existing.reg_ip = reg_ip
                existing.last_seen = datetime.now(timezone.utc)
                self._store.upsert(existing)
                return existing
            if self._require_invitation and not self._enrollment.consume(req.invitation or "", req.vdom):
                raise RegistrationError("a valid unused invitation for this group is required")
            token = secrets.token_urlsafe(32)
            endpoint = Endpoint(
                devid=req.devid, client_id=self._new_client_id(), hostname=req.hostname,
                os=req.os, fctver=req.fctver, vdom=req.vdom, reg_ip=reg_ip,
                credential_hash=self._credential_hash(token), device_token=token,
            )
            if not self._store.create(endpoint):
                raise RegistrationError("device already exists; proof of possession is required")
            return endpoint

    @staticmethod
    def _credential_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def authenticate_device(self, client_id: str, token: str) -> bool:
        endpoint = self._store.get_by_client_id(client_id)
        return bool(
            endpoint is not None and endpoint.status is not EndpointStatus.UNREGISTERED
            and token and len(token) <= 512 and endpoint.credential_hash
            and hmac.compare_digest(endpoint.credential_hash, self._credential_hash(token))
        )

    def create_invitation(self, vdom: str = "Default", max_uses: int = 1, ttl_seconds: int = 3600) -> str:
        token = secrets.token_urlsafe(32)
        self._enrollment.add(token, vdom, max_uses, datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds))
        return token

    def rotate_device_token(self, devid: str) -> str:
        endpoint = self.get_endpoint(devid)
        if endpoint.status is EndpointStatus.UNREGISTERED:
            raise RegistrationError("device is revoked")
        token = secrets.token_urlsafe(32)
        endpoint.credential_hash = self._credential_hash(token)
        self._store.upsert(endpoint)
        return token

    def revoke_device(self, devid: str) -> None:
        endpoint = self.get_endpoint(devid)
        endpoint.credential_hash = ""
        endpoint.status = EndpointStatus.UNREGISTERED
        self._store.upsert(endpoint)

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

    def get_endpoint(self, devid: str) -> Endpoint:
        endpoint = self._store.get_by_devid(devid)
        if endpoint is None:
            raise UnknownEndpointError(devid)
        return endpoint

    def get_endpoint_by_client_id(self, client_id: str) -> Endpoint:
        endpoint = self._store.get_by_client_id(client_id)
        if endpoint is None:
            raise UnknownEndpointError(client_id)
        return endpoint

    def count(self) -> int:
        return len(self._store.all())

    def host_tags_by_devid(self, devid: str) -> list[str]:
        endpoint = self._store.get_by_devid(devid)
        if endpoint is None:
            raise UnknownEndpointError(devid)
        return endpoint.host_tags

    # --- config / profile push ------------------------------------------

    def set_profile(self, vdom: str, body: dict[str, Any]) -> Profile:
        """Publish a new profile for a vdom and notify its endpoints.

        Bumps the version and enqueues a `config_update` message for every
        registered endpoint in that vdom; endpoints pull it and then fetch the
        profile via get_profile().
        """
        previous = self._profile_store.get(vdom)
        profile = Profile(
            vdom=vdom,
            version=(previous.version + 1) if previous else 1,
            body=validate_policy(body),
        )
        self._profile_store.put(profile)
        for endpoint in self._store.all():
            if self.effective_vdom(endpoint) == vdom:
                self._queue.push(
                    endpoint.client_id,
                    {"type": "config_update", "vdom": vdom, "version": profile.version},
                )
        return profile

    def get_profile(self, vdom: str) -> Profile:
        profile = self._profile_store.get(vdom)
        if profile is None:
            raise UnknownProfileError(vdom)
        return profile

    def list_profiles(self) -> list[Profile]:
        return self._profile_store.all()

    def current_config_version(self, vdom: str) -> int:
        profile = self._profile_store.get(vdom)
        return profile.version if profile else 0

    # --- group assignment rules -----------------------------------------

    def add_rule(self, rule: AssignmentRule) -> None:
        """Add a rule, replacing any existing rule with the same id (upsert)."""
        self._rule_store.add(rule)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove the rule with this id; return True if one was removed."""
        return self._rule_store.remove(rule_id)

    def list_rules(self) -> list[AssignmentRule]:
        return self._rule_store.all()

    def effective_vdom(self, endpoint: Endpoint) -> str:
        """The vdom assigned to an endpoint: first matching rule, else its own."""
        return evaluate_rules(endpoint, self._rule_store.all()) or endpoint.vdom

    def effective_profile(self, client_id: str) -> Profile | None:
        """Resolve the profile an endpoint should run, via its effective vdom."""
        endpoint = self._store.get_by_client_id(client_id)
        if endpoint is None:
            raise UnknownEndpointError(client_id)
        return self._profile_store.get(self.effective_vdom(endpoint))

    def pull_messages(self, client_id: str) -> list[dict[str, Any]]:
        """Drain pending push notifications for an endpoint (config updates, …)."""
        if self._store.get_by_client_id(client_id) is None:
            raise UnknownEndpointError(client_id)
        return self._queue.pull(client_id)

    def ack_config(
        self, client_id: str, version: int, *, vdom: str | None = None,
        digest: str | None = None, success: bool = True, error: str = "",
    ) -> Endpoint:
        """Record that the endpoint has applied a given profile version."""
        endpoint = self._store.get_by_client_id(client_id)
        if endpoint is None:
            raise UnknownEndpointError(client_id)
        profile = self.effective_profile(client_id)
        if (profile is None or version != profile.version
                or (vdom is not None and vdom != profile.vdom)
                or (digest is not None and digest != profile.digest)):
            raise ValueError("acknowledgment does not match assigned policy")
        if success:
            endpoint.config_version = profile.version
            endpoint.applied_vdom = profile.vdom
            endpoint.applied_digest = profile.digest
            endpoint.last_applied = datetime.now(timezone.utc)
            endpoint.last_error = ""
        else:
            endpoint.last_error = error[:1000] or "policy application failed"
        endpoint.last_seen = datetime.now(timezone.utc)
        self._store.upsert(endpoint)
        return endpoint

    # --- helpers --------------------------------------------------------

    @property
    def ems_serial(self) -> str:
        return self._ems_serial

    @staticmethod
    def _new_client_id() -> str:
        return secrets.token_hex(16)
