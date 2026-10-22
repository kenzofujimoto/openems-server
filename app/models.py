"""Domain models for an interoperable, clean-room endpoint-management server.

Derived solely from the behavioural interoperability spec (SPEC-INTEROP.md),
not from any proprietary source. Field names mirror the observed wire protocol
so a compatible agent can be understood; the implementation here is original.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


def _utcnow() -> datetime:
    return datetime.now(UTC)


class EndpointStatus(str, Enum):
    REGISTERED = "registered"
    UNREGISTERED = "unregistered"
    QUARANTINED = "quarantined"


@dataclass(slots=True)
class RegisterRequest:
    """Payload an agent sends to /fct/api/public/v1/register/.

    Only the identity fields observed in the agent binaries are modelled.
    The exact serialization (JSON vs protobuf) is still to be captured from a
    lab EMS; this server speaks JSON by default.
    """

    devid: str
    fctver: str = ""
    os: str = ""
    hostname: str = ""
    vdom: str = "Default"
    invitation: str | None = None
    key: str | None = None


@dataclass(slots=True)
class Endpoint:
    devid: str
    client_id: str
    hostname: str = ""
    os: str = ""
    fctver: str = ""
    vdom: str = "Default"
    status: EndpointStatus = EndpointStatus.REGISTERED
    reg_ip: str = ""
    host_tags: list[str] = field(default_factory=list)
    config_version: int = 0  # profile version this endpoint has applied
    last_seen: datetime = field(default_factory=_utcnow)
    created_at: datetime = field(default_factory=_utcnow)
    credential_hash: str = field(default="", repr=False)
    device_token: str = field(default="", repr=False, compare=False)
    applied_vdom: str = ""
    applied_digest: str = ""
    last_error: str = ""
    last_applied: datetime | None = None


@dataclass(slots=True)
class Profile:
    """A configuration profile pushed to every endpoint in a vdom.

    `version` increases on each update; endpoints compare it against their own
    `config_version` to decide whether to fetch `body`.
    """

    vdom: str
    version: int = 0
    body: dict[str, Any] = field(default_factory=dict)
    updated_at: datetime = field(default_factory=_utcnow)

    @property
    def digest(self) -> str:
        from agent.policy import policy_digest

        return policy_digest(self.body)


@dataclass(slots=True)
class Condition:
    """One predicate matched against an endpoint attribute.

    field: os | hostname | fctver | vdom | host_tag
    op:    equals | contains | in | has_tag   (has_tag applies to host_tag)
    value: str for equals/contains/has_tag; list[str] for in
    """

    field: str
    op: str
    value: Any


@dataclass(slots=True)
class AssignmentRule:
    """A group-assignment rule: if all conditions match, assign target_vdom.

    Rules are evaluated by ascending `priority` (lower wins); the first matching
    enabled rule decides the endpoint's effective vdom/profile.
    """

    id: str
    target_vdom: str
    conditions: list[Condition] = field(default_factory=list)
    priority: int = 100
    enabled: bool = True
