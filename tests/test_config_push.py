"""Service-level tests for config/profile push (SPEC-INTEROP.md §2.4)."""

from __future__ import annotations

import pytest

from app.models import RegisterRequest
from app.service import EmsService, UnknownEndpointError, UnknownProfileError


def test_set_profile_bumps_version() -> None:
    svc = EmsService(require_invitation=False)
    p1 = svc.set_profile("Default", {"av": "on"})
    p2 = svc.set_profile("Default", {"av": "off"})
    assert (p1.version, p2.version) == (1, 2)
    assert svc.get_profile("Default").body == {"av": "off"}


def test_get_profile_unknown_vdom_raises() -> None:
    svc = EmsService(require_invitation=False)
    with pytest.raises(UnknownProfileError):
        svc.get_profile("nope")


def test_setting_profile_enqueues_update_for_vdom_endpoints() -> None:
    svc = EmsService(require_invitation=False)
    ep = svc.register(RegisterRequest(devid="DEV-1", vdom="Default"))
    svc.register(RegisterRequest(devid="DEV-2", vdom="Other"))

    svc.set_profile("Default", {"firewall": "strict"})

    msgs = svc.pull_messages(ep.client_id)
    assert msgs == [{"type": "config_update", "vdom": "Default", "version": 1}]


def test_endpoint_in_other_vdom_gets_no_update() -> None:
    svc = EmsService(require_invitation=False)
    svc.register(RegisterRequest(devid="DEV-1", vdom="Default"))
    other = svc.register(RegisterRequest(devid="DEV-2", vdom="Other"))
    svc.set_profile("Default", {"x": 1})
    assert svc.pull_messages(other.client_id) == []


def test_pull_messages_drains() -> None:
    svc = EmsService(require_invitation=False)
    ep = svc.register(RegisterRequest(devid="DEV-1", vdom="Default"))
    svc.set_profile("Default", {"x": 1})
    svc.pull_messages(ep.client_id)
    assert svc.pull_messages(ep.client_id) == []


def test_ack_config_records_applied_version() -> None:
    svc = EmsService(require_invitation=False)
    ep = svc.register(RegisterRequest(devid="DEV-1", vdom="Default"))
    svc.set_profile("Default", {"x": 1})
    updated = svc.ack_config(ep.client_id, 1)
    assert updated.config_version == 1


def test_pull_messages_unknown_client_raises() -> None:
    svc = EmsService(require_invitation=False)
    with pytest.raises(UnknownEndpointError):
        svc.pull_messages("nope")
