"""Strict HTTP input contracts for the reference-agent protocol."""

import ipaddress
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class RegisterPayload(InputModel):
    devid: str = Field(min_length=1, max_length=256)
    hostname: str = Field(default="", max_length=256)
    os: str = Field(default="", max_length=128)
    fctver: str = Field(default="", max_length=128)
    vdom: str = Field(default="Default", min_length=1, max_length=128)
    invitation: str | None = Field(default=None, max_length=512)
    key: str | None = Field(default=None, max_length=512)


class ClientPayload(InputModel):
    client_id: str = Field(min_length=1, max_length=128)


class TagsPayload(ClientPayload):
    tags: list[str] = Field(default_factory=list, max_length=256)

    @field_validator("tags")
    @classmethod
    def bounded_tags(cls, tags: list[str]) -> list[str]:
        if any(not tag or len(tag) > 256 for tag in tags):
            raise ValueError("tags must be nonempty strings of at most 256 characters")
        return list(dict.fromkeys(tags))


class EventRowPayload(InputModel):
    hour: str = Field(min_length=1, max_length=40)
    domain: str = Field(min_length=1, max_length=255)
    reason: Literal["rule", "category", "doh"]
    category: str | None = Field(default=None, max_length=32)
    count: int = Field(ge=1, le=100_000)


class EventsPayload(ClientPayload):
    events: list[EventRowPayload] = Field(default_factory=list, max_length=5000)
    dropped: int = Field(default=0, ge=0, le=10_000_000)


class TamperRowPayload(InputModel):
    at: str = Field(min_length=1, max_length=40)
    kind: Literal["dns_rule_restored", "wfp_restored", "browser_policy_restored", "hosts_restored",
                  "service_config_restored", "watchdog_restored", "service_started_by_watchdog", "unexpected_exit",
                  "uninstall_code_rejected", "uninstall_without_secret"]
    detail: str = Field(min_length=1, max_length=200)


class TamperPayload(ClientPayload):
    events: list[TamperRowPayload] = Field(default_factory=list, max_length=200)
    dropped: int = Field(default=0, ge=0, le=1_000_000)


class AckPayload(ClientPayload):
    vdom: str | None = Field(default=None, min_length=1, max_length=128)
    version: int = Field(ge=0)
    digest: str | None = Field(default=None, max_length=64)
    success: bool = True
    error: str = Field(default="", max_length=1000)
    location: str = Field(default="", max_length=128)


def _hostname(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError("invalid DNS name") from error
    if not value or len(value) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in value.split(".")
    ):
        raise ValueError("invalid DNS name")
    return value


class LocationProbePayload(InputModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=443, ge=1, le=65535)
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")

    @field_validator("host")
    @classmethod
    def valid_host(cls, value: str) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return _hostname(value)

    @field_validator("sha256")
    @classmethod
    def normalized_pin(cls, value: str) -> str:
        return value.lower()


class NetworkLocationPayload(InputModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,127}$")
    name: str = Field(min_length=1, max_length=128)
    cidrs: list[str] = Field(default_factory=list, max_length=128)
    gateway_macs: list[str] = Field(default_factory=list, max_length=128)
    dns_suffixes: list[str] = Field(default_factory=list, max_length=128)
    public_cidrs: list[str] = Field(default_factory=list, max_length=128)
    probe: LocationProbePayload | None = None

    @field_validator("name")
    @classmethod
    def nonempty_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("location name must not be empty")
        return value.strip()

    @field_validator("cidrs", "public_cidrs")
    @classmethod
    def valid_cidrs(cls, values: list[str]) -> list[str]:
        try:
            return list(dict.fromkeys(str(ipaddress.ip_network(value, strict=False)) for value in values))
        except ValueError as error:
            raise ValueError("invalid CIDR range") from error

    @field_validator("gateway_macs")
    @classmethod
    def valid_macs(cls, values: list[str]) -> list[str]:
        result = []
        for value in values:
            normalized = re.sub(r"[:.\- ]", "", value).lower()
            if not re.fullmatch(r"[a-f0-9]{12}", normalized):
                raise ValueError("invalid gateway MAC address")
            result.append(normalized)
        return list(dict.fromkeys(result))

    @field_validator("dns_suffixes")
    @classmethod
    def valid_suffixes(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(_hostname(value) for value in values))

    @model_validator(mode="after")
    def enough_signals(self) -> "NetworkLocationPayload":
        if not self.public_cidrs and sum(bool(signal) for signal in (
            self.cidrs, self.gateway_macs, self.dns_suffixes, self.probe
        )) < 2:
            raise ValueError("a location needs a public range or two distinct local signal types")
        return self


class LocationPolicyPayload(InputModel):
    vdom: str = Field(min_length=1, max_length=128)
    location_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,127}$")
    inside_vdom: str = Field(min_length=1, max_length=128)


class ConditionPayload(InputModel):
    field: Literal["os", "hostname", "fctver", "vdom", "host_tag"]
    op: Literal["equals", "contains", "in", "has_tag"]
    value: str | list[str]

    @model_validator(mode="after")
    def operator_type(self) -> "ConditionPayload":
        if self.op == "in" and not isinstance(self.value, list):
            raise ValueError("in requires a list of strings")
        if self.op != "in" and not isinstance(self.value, str):
            raise ValueError("this operator requires a string")
        if (self.field == "host_tag") != (self.op == "has_tag"):
            raise ValueError("host_tag requires has_tag")
        values = self.value if isinstance(self.value, list) else [self.value]
        if len(values) > 256 or any(len(value) > 512 for value in values):
            raise ValueError("condition values exceed allowed size")
        return self


class RulePayload(InputModel):
    id: str = Field(min_length=1, max_length=128)
    target_vdom: str = Field(min_length=1, max_length=128)
    priority: int = Field(default=100, ge=0, le=1_000_000)
    enabled: bool = True
    conditions: list[ConditionPayload] = Field(default_factory=list, max_length=32)


class LoginPayload(InputModel):
    username: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=4096)


class InvitationPayload(InputModel):
    vdom: str = Field(default="Default", min_length=1, max_length=128)
    max_uses: int = Field(default=1, ge=1, le=1000)
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)


class DevicePayload(InputModel):
    devid: str = Field(min_length=1, max_length=256)


class DeliveryProofPayload(ClientPayload):
    proof: str = Field(pattern=r"^[0-9a-f]{64}$")


class ReleasePayload(InputModel):
    scope: str = Field(min_length=1, max_length=128)  # a policy group, or "*" for the whole fleet
    released: bool


class IdpPayload(InputModel):
    prefix: str = Field(default="Default", min_length=1, max_length=128)
    metadata: str = Field(min_length=1, max_length=512_000)


def profile_response(profile: Any) -> dict[str, Any]:
    return {"vdom": profile.vdom, "version": profile.version, "digest": profile.digest, "body": profile.body}
