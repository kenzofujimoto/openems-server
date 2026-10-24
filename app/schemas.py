"""Strict HTTP input contracts for the reference-agent protocol."""

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
                  "service_config_restored", "watchdog_restored", "service_started_by_watchdog", "unexpected_exit"]
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


class IdpPayload(InputModel):
    prefix: str = Field(default="Default", min_length=1, max_length=128)
    metadata: str = Field(min_length=1, max_length=512_000)


def profile_response(profile: Any) -> dict[str, Any]:
    return {"vdom": profile.vdom, "version": profile.version, "digest": profile.digest, "body": profile.body}
