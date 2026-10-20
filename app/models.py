"""Domain models for an interoperable, clean-room endpoint-management server.

Derived solely from the behavioural interoperability spec (SPEC-INTEROP.md),
not from any proprietary source. Field names mirror the observed wire protocol
so a compatible agent can be understood; the implementation here is original.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


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
    invitation: Optional[str] = None
    key: Optional[str] = None


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
    last_seen: datetime = field(default_factory=_utcnow)
    created_at: datetime = field(default_factory=_utcnow)
