"""Behavioural tests for the clean-room EmsService.

These encode the contract from SPEC-INTEROP.md sections 2-3. They use no network
or web framework, so the suite runs with only the standard library + pytest.
"""

from __future__ import annotations

import pytest

from app.models import EndpointStatus, RegisterRequest
from app.service import (
    EmsService,
    RegistrationError,
    UnknownEndpointError,
)


def test_register_creates_endpoint_with_client_id() -> None:
    svc = EmsService(require_invitation=False)
    ep = svc.register(RegisterRequest(devid="DEV-1", hostname="pc1", os="Windows"))
    assert ep.devid == "DEV-1"
    assert ep.client_id  # a non-empty client id was assigned
    assert ep.status is EndpointStatus.REGISTERED
    assert svc.count() == 1


def test_register_requires_devid() -> None:
    svc = EmsService(require_invitation=False)
    with pytest.raises(RegistrationError):
        svc.register(RegisterRequest(devid=""))


def test_register_is_idempotent_on_devid() -> None:
    svc = EmsService(require_invitation=False)
    first = svc.register(RegisterRequest(devid="DEV-1"))
    second = svc.register(RegisterRequest(devid="DEV-1", hostname="renamed"))
    assert first.client_id == second.client_id  # same endpoint, not a duplicate
    assert svc.count() == 1


def test_invitation_required_rejects_without_code() -> None:
    svc = EmsService(require_invitation=True, valid_invitations={"GOOD"})
    with pytest.raises(RegistrationError):
        svc.register(RegisterRequest(devid="DEV-1"))
    ep = svc.register(RegisterRequest(devid="DEV-1", invitation="GOOD"))
    assert ep.status is EndpointStatus.REGISTERED


def test_update_client_id_rotates_identifier() -> None:
    svc = EmsService(require_invitation=False)
    ep = svc.register(RegisterRequest(devid="DEV-1"))
    old = ep.client_id
    rotated = svc.update_client_id(old)
    assert rotated.client_id != old
    assert rotated.devid == "DEV-1"


def test_refresh_unknown_client_raises() -> None:
    svc = EmsService(require_invitation=False)
    with pytest.raises(UnknownEndpointError):
        svc.refresh("does-not-exist")


def test_host_tags_ingested_and_queryable_by_devid() -> None:
    svc = EmsService(require_invitation=False)
    ep = svc.register(RegisterRequest(devid="DEV-1"))
    svc.ingest_host_tags(ep.client_id, ["compliant", "av-on"])
    assert svc.host_tags_by_devid("DEV-1") == ["compliant", "av-on"]
