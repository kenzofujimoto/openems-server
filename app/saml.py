"""Minimal SAML 2.0 Service Provider (SP) core — clean-room.

Implements the standard OASIS SAML 2.0 web-browser SSO profile pieces the EMS
exposes (SPEC-INTEROP.md §4): SP metadata, an AuthnRequest (HTTP-Redirect
binding) and parsing of a SAMLResponse at the ACS (HTTP-POST binding). SAML is a
public standard, so this is an original implementation of that standard.

Security defaults require a signed whole Response, mandatory validity and recipient
checks, correlation with an outstanding AuthnRequest, and atomic replay protection.
Explicit require_signature=False is reserved for parser fixtures and local labs.
"""

from __future__ import annotations

import base64
import secrets
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode
from xml.etree import ElementTree as ET

from .idp_store import IdpStore, InMemoryIdpStore
from .replay import (
    InMemoryPendingRequestStore,
    InMemoryReplayCache,
    PendingRequestStore,
    ReplayCache,
)

SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
MD = "urn:oasis:names:tc:SAML:2.0:metadata"
DS = "http://www.w3.org/2000/09/xmldsig#"
BIND_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
BIND_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"


class SamlError(Exception):
    """Raised when a SAML message is malformed or not successful."""


@dataclass(slots=True)
class SpConfig:
    entity_id: str  # SP EntityID (this EMS)
    acs_url: str  # Assertion Consumer Service URL


@dataclass(slots=True)
class IdpConfig:
    entity_id: str  # IdP EntityID
    sso_url: str  # IdP SingleSignOnService (HTTP-Redirect)
    certificate: str | None = None  # IdP signing cert (PEM body), if known


@dataclass(slots=True)
class SamlAssertion:
    name_id: str
    attributes: dict[str, list[str]] = field(default_factory=dict)
    session_index: str | None = None
    assertion_id: str | None = None
    not_before: datetime | None = None
    not_on_or_after: datetime | None = None
    audiences: list[str] = field(default_factory=list)
    issuer: str | None = None
    response_issuer: str | None = None
    destination: str | None = None
    recipient: str | None = None
    in_response_to: str | None = None
    subject_in_response_to: str | None = None
    subject_expiry: datetime | None = None
    response_id: str | None = None
    audience_restrictions: list[list[str]] = field(default_factory=list)


def _utcnow_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id() -> str:
    return "_" + secrets.token_hex(16)


# --- SP metadata --------------------------------------------------------


def build_sp_metadata(sp: SpConfig) -> str:
    ed = ET.Element(f"{{{MD}}}EntityDescriptor", {"entityID": sp.entity_id})
    spd = ET.SubElement(
        ed,
        f"{{{MD}}}SPSSODescriptor",
        {"protocolSupportEnumeration": SAMLP, "WantAssertionsSigned": "true"},
    )
    ET.SubElement(
        spd,
        f"{{{MD}}}AssertionConsumerService",
        {
            "Binding": BIND_POST,
            "Location": sp.acs_url,
            "index": "0",
            "isDefault": "true",
        },
    )
    return ET.tostring(ed, encoding="unicode")


# --- AuthnRequest (SP -> IdP, HTTP-Redirect) ----------------------------


def build_authn_request(
    sp: SpConfig, idp: IdpConfig, *, relay_state: str | None = None
) -> tuple[str, str]:
    """Return (request_id, redirect_url) for the HTTP-Redirect binding."""
    req_id = _new_id()
    req = ET.Element(
        f"{{{SAMLP}}}AuthnRequest",
        {
            "ID": req_id,
            "Version": "2.0",
            "IssueInstant": _utcnow_iso(),
            "Destination": idp.sso_url,
            "ProtocolBinding": BIND_POST,
            "AssertionConsumerServiceURL": sp.acs_url,
        },
    )
    issuer = ET.SubElement(req, f"{{{SAML}}}Issuer")
    issuer.text = sp.entity_id
    xml = ET.tostring(req, encoding="unicode")

    # HTTP-Redirect binding: raw-DEFLATE, base64, urlencode.
    deflated = _raw_deflate(xml.encode("utf-8"))
    params = {"SAMLRequest": base64.b64encode(deflated).decode("ascii")}
    if relay_state is not None:
        params["RelayState"] = relay_state
    sep = "&" if "?" in idp.sso_url else "?"
    return req_id, f"{idp.sso_url}{sep}{urlencode(params)}"


# --- SAMLResponse parsing (IdP -> SP ACS, HTTP-POST) --------------------


def parse_saml_response(
    saml_response_b64: str,
    *,
    verify_signature: Callable[[bytes], ET.Element | None] | None = None,
    require_signature: bool = True,
) -> SamlAssertion:
    if len(saml_response_b64) > 1_400_000:
        raise SamlError("SAMLResponse exceeds size limit")
    try:
        xml_bytes = base64.b64decode(saml_response_b64, validate=True)
    except (ValueError, TypeError) as err:
        raise SamlError("SAMLResponse is not valid base64") from err

    if (
        len(xml_bytes) > 1_000_000
        or b"<!DOCTYPE" in xml_bytes.upper()
        or b"<!ENTITY" in xml_bytes.upper()
    ):
        raise SamlError("SAMLResponse XML exceeds limits or contains a DTD")
    if require_signature:
        root = verify_signature(xml_bytes) if verify_signature is not None else None
        if not isinstance(root, ET.Element):
            raise SamlError("SAMLResponse signature could not be verified")
    else:
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError as err:
            raise SamlError("SAMLResponse is not well-formed XML") from err

    if root.tag != f"{{{SAMLP}}}Response":
        raise SamlError("Expected a SAML Response root")
    assertions = list(root.iter(f"{{{SAML}}}Assertion"))
    if len(assertions) != 1 or root.find(f"{{{SAML}}}Assertion") is not assertions[0]:
        raise SamlError("Response must contain exactly one direct Assertion")
    ids = [node.get("ID") for node in root.iter() if node.get("ID")]
    if len(set(ids)) != len(ids):
        raise SamlError("Response contains duplicate IDs")

    status = root.find(f"{{{SAMLP}}}Status/{{{SAMLP}}}StatusCode")
    if status is None or status.get("Value") != STATUS_SUCCESS:
        code = status.get("Value") if status is not None else "missing"
        raise SamlError(f"SAML status not Success: {code}")

    assertion = root.find(f"{{{SAML}}}Assertion")
    if assertion is None:
        raise SamlError("SAMLResponse has no Assertion")

    name_id_el = assertion.find(f"{{{SAML}}}Subject/{{{SAML}}}NameID")
    if name_id_el is None or not (name_id_el.text or "").strip():
        raise SamlError("Assertion has no NameID")
    name_id = name_id_el.text.strip()

    attributes: dict[str, list[str]] = {}
    for attr in assertion.findall(f"{{{SAML}}}AttributeStatement/{{{SAML}}}Attribute"):
        name = attr.get("Name", "")
        values = [(v.text or "") for v in attr.findall(f"{{{SAML}}}AttributeValue")]
        if name:
            attributes[name] = values

    authn = assertion.find(f"{{{SAML}}}AuthnStatement")
    session_index = authn.get("SessionIndex") if authn is not None else None

    conditions = assertion.find(f"{{{SAML}}}Conditions")
    not_before = not_on_or_after = None
    audiences: list[str] = []
    if conditions is not None:
        not_before = _parse_dt(conditions.get("NotBefore"))
        not_on_or_after = _parse_dt(conditions.get("NotOnOrAfter"))
        audiences = [
            (a.text or "").strip()
            for a in conditions.findall(
                f"{{{SAML}}}AudienceRestriction/{{{SAML}}}Audience"
            )
            if (a.text or "").strip()
        ]

    confirmation = assertion.find(f"{{{SAML}}}Subject/{{{SAML}}}SubjectConfirmation")
    subject_data = (
        confirmation.find(f"{{{SAML}}}SubjectConfirmationData")
        if confirmation is not None
        else None
    )
    if require_signature and (
        confirmation is None
        or confirmation.get("Method") != "urn:oasis:names:tc:SAML:2.0:cm:bearer"
    ):
        raise SamlError("Assertion requires bearer SubjectConfirmation")
    if (
        require_signature
        and len(assertion.findall(f"{{{SAML}}}Subject/{{{SAML}}}SubjectConfirmation"))
        != 1
    ):
        raise SamlError("Assertion requires exactly one SubjectConfirmation")
    return SamlAssertion(
        name_id=name_id,
        attributes=attributes,
        session_index=session_index,
        assertion_id=assertion.get("ID"),
        not_before=not_before,
        not_on_or_after=not_on_or_after,
        audiences=audiences,
        issuer=assertion.findtext(f"{{{SAML}}}Issuer"),
        response_issuer=root.findtext(f"{{{SAML}}}Issuer"),
        response_id=root.get("ID"),
        destination=root.get("Destination"),
        in_response_to=root.get("InResponseTo"),
        recipient=subject_data.get("Recipient") if subject_data is not None else None,
        subject_in_response_to=subject_data.get("InResponseTo")
        if subject_data is not None
        else None,
        subject_expiry=_parse_dt(subject_data.get("NotOnOrAfter"))
        if subject_data is not None
        else None,
        audience_restrictions=[
            [(a.text or "").strip() for a in restriction.findall(f"{{{SAML}}}Audience")]
            for restriction in conditions.findall(f"{{{SAML}}}AudienceRestriction")
        ]
        if conditions is not None
        else [],
    )


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)  # Python 3.11+ accepts the trailing 'Z'
    except ValueError as err:
        raise SamlError("Malformed SAML timestamp") from err
    if dt.tzinfo is None:
        raise SamlError("SAML timestamps require timezone")
    return dt


def validate_conditions(
    assertion: SamlAssertion,
    *,
    audience: str | None = None,
    now: datetime | None = None,
    clock_skew_seconds: int = 60,
    require_audience: bool = False,
) -> None:
    """Enforce the SAML assertion validity window and audience restriction.

    Raises SamlError on an expired/not-yet-valid assertion or an audience
    mismatch. `clock_skew_seconds` tolerates small IdP/SP clock drift.
    """
    now = now or datetime.now(UTC)
    skew = timedelta(seconds=clock_skew_seconds)

    if assertion.not_before is not None and now + skew < assertion.not_before:
        raise SamlError("assertion is not yet valid (NotBefore)")
    if (
        assertion.not_on_or_after is not None
        and now - skew >= assertion.not_on_or_after
    ):
        raise SamlError("assertion has expired (NotOnOrAfter)")

    if audience is not None:
        if assertion.audiences:
            if audience not in assertion.audiences or any(
                audience not in restriction
                for restriction in assertion.audience_restrictions
            ):
                raise SamlError("assertion audience does not include this SP")
        elif require_audience:
            raise SamlError("assertion has no AudienceRestriction")


# --- IdP metadata import ------------------------------------------------


def parse_idp_metadata(xml_text: str) -> IdpConfig:
    if (
        len(xml_text) > 1_000_000
        or "<!DOCTYPE" in xml_text.upper()
        or "<!ENTITY" in xml_text.upper()
    ):
        raise SamlError("IdP metadata exceeds limits or contains a DTD")
    try:
        ed = ET.fromstring(xml_text)
    except ET.ParseError as err:
        raise SamlError("IdP metadata is not well-formed XML") from err

    entity_id = ed.get("entityID")
    idp_desc = ed.find(f"{{{MD}}}IDPSSODescriptor")
    if entity_id is None or idp_desc is None:
        raise SamlError("not a SAML IdP EntityDescriptor")

    sso = idp_desc.find(f"{{{MD}}}SingleSignOnService[@Binding='{BIND_REDIRECT}']")
    if sso is None:
        sso = idp_desc.find(f"{{{MD}}}SingleSignOnService")
    if sso is None or not sso.get("Location"):
        raise SamlError("IdP metadata has no SingleSignOnService")

    cert_el = idp_desc.find(f"{{{MD}}}KeyDescriptor//{{{DS}}}X509Certificate")
    certificate = (cert_el.text or "").strip() if cert_el is not None else None

    return IdpConfig(
        entity_id=entity_id, sso_url=sso.get("Location"), certificate=certificate
    )


def _raw_deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


class UnknownIdpError(SamlError):
    """Raised when a tenant prefix has no registered IdP."""


class SamlSp:
    """Multi-tenant SAML SP: one SP identity, many IdPs keyed by URL prefix.

    Mirrors the observed `/fct_saml/{prefix}/...` routing, where each tenant/site
    binds its own IdP. The SP EntityID and ACS are templated with the prefix so
    each tenant gets a distinct ACS URL.
    """

    def __init__(
        self,
        base_url: str,
        *,
        require_signature: bool = True,
        validate_conditions: bool = True,
        require_audience: bool = True,
        clock_skew_seconds: int = 60,
        replay_cache: ReplayCache | None = None,
        idp_store: IdpStore | None = None,
        pending_store: PendingRequestStore | None = None,
        request_ttl_seconds: int = 300,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._require_signature = require_signature
        self._validate_conditions = validate_conditions
        self._require_audience = require_audience
        self._clock_skew_seconds = clock_skew_seconds
        self._replay_cache: ReplayCache = replay_cache or InMemoryReplayCache()
        if clock_skew_seconds < 0 or request_ttl_seconds <= 0:
            raise ValueError("SAML skew and request TTL must be non-negative/positive")
        self._idp_store = idp_store or InMemoryIdpStore()
        self._pending_store = pending_store or InMemoryPendingRequestStore()
        self._request_ttl_seconds = request_ttl_seconds

    def sp_config(self, prefix: str) -> SpConfig:
        return SpConfig(
            entity_id=f"{self._base_url}/fct_saml/{prefix}/metadata",
            acs_url=f"{self._base_url}/fct_saml/{prefix}/acs",
        )

    def register_idp(self, prefix: str, idp: IdpConfig) -> None:
        if self._require_signature and not idp.certificate:
            raise SamlError("IdP signing certificate is required")
        self._idp_store.put(prefix, idp)

    def register_idp_from_metadata(self, prefix: str, metadata_xml: str) -> IdpConfig:
        idp = parse_idp_metadata(metadata_xml)
        if self._require_signature and not idp.certificate:
            raise SamlError("IdP signing certificate is required")
        self._idp_store.put(prefix, idp)
        return idp

    def _idp(self, prefix: str) -> IdpConfig:
        idp = self._idp_store.get(prefix)
        if idp is None:
            raise UnknownIdpError(prefix)
        return idp

    def metadata(self, prefix: str) -> str:
        return build_sp_metadata(self.sp_config(prefix))

    def login_redirect(self, prefix: str, *, relay_state: str | None = None) -> str:
        request_id, url = build_authn_request(
            self.sp_config(prefix), self._idp(prefix), relay_state=relay_state
        )
        self._pending_store.put(
            request_id,
            prefix,
            relay_state,
            datetime.now(UTC) + timedelta(seconds=self._request_ttl_seconds),
        )
        return url

    def consume(
        self,
        prefix: str,
        saml_response_b64: str,
        *,
        relay_state: str | None = None,
        now: datetime | None = None,
    ) -> SamlAssertion:
        idp = self._idp(prefix)  # ensure the tenant exists before trusting a response
        verifier: Callable[[bytes], ET.Element | None] | None = None
        if self._require_signature and idp.certificate:
            from .saml_signatures import certificate_to_pem, make_signxml_verifier

            verifier = make_signxml_verifier(certificate_to_pem(idp.certificate))

        assertion = parse_saml_response(
            saml_response_b64,
            verify_signature=verifier,
            require_signature=self._require_signature,
        )

        current = now or datetime.now(UTC)
        if self._require_signature:
            self._validate_binding(prefix, idp, assertion, current)

        if self._validate_conditions or self._require_signature:
            validate_conditions(
                assertion,
                audience=self.sp_config(prefix).entity_id,
                now=now,
                clock_skew_seconds=self._clock_skew_seconds,
                require_audience=self._require_audience or self._require_signature,
            )

        if self._require_signature and not self._pending_store.consume(
            assertion.in_response_to or "", prefix, relay_state
        ):
            raise SamlError(
                "SAML response has no matching outstanding request or RelayState"
            )

        if assertion.assertion_id:
            # Every instant accepted by the clock-skew rule must remain protected.
            expires_at = (assertion.not_on_or_after or current) + timedelta(
                seconds=self._clock_skew_seconds
            )
            key = f"{prefix}:{idp.entity_id}:{assertion.assertion_id}"
            if not self._replay_cache.check_and_remember(key, expires_at):
                raise SamlError("assertion replay detected")
        return assertion

    def _validate_binding(
        self, prefix: str, idp: IdpConfig, assertion: SamlAssertion, now: datetime
    ) -> None:
        if not assertion.assertion_id or not assertion.response_id:
            raise SamlError("Response and Assertion require IDs")
        if (
            assertion.issuer != idp.entity_id
            or assertion.response_issuer != idp.entity_id
        ):
            raise SamlError("SAML issuer does not match registered IdP")
        acs = self.sp_config(prefix).acs_url
        if assertion.destination != acs or assertion.recipient != acs:
            raise SamlError("SAML destination/recipient does not match ACS")
        if (
            not assertion.in_response_to
            or assertion.subject_in_response_to != assertion.in_response_to
        ):
            raise SamlError("SAML InResponseTo is missing or inconsistent")
        if assertion.not_on_or_after is None or assertion.subject_expiry is None:
            raise SamlError("SAML assertion and SubjectConfirmation require expiry")
        if (
            now - timedelta(seconds=self._clock_skew_seconds)
            >= assertion.subject_expiry
        ):
            raise SamlError("SAML SubjectConfirmation has expired")
