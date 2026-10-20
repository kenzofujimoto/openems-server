"""Minimal SAML 2.0 Service Provider (SP) core — clean-room.

Implements the standard OASIS SAML 2.0 web-browser SSO profile pieces the EMS
exposes (SPEC-INTEROP.md §4): SP metadata, an AuthnRequest (HTTP-Redirect
binding) and parsing of a SAMLResponse at the ACS (HTTP-POST binding). SAML is a
public standard, so this is an original implementation of that standard.

SECURITY NOTE — XML-DSig signature verification is wired through a pluggable
hook. `SamlSp(require_signature=True)` builds a signxml-based verifier from the
registered IdP certificate (see app/saml_signatures.py) and refuses any response
whose enveloped signature does not verify. It is OFF by default so the core can
be tested without crypto; enable it in production, and additionally validate the
assertion conditions (NotOnOrAfter, Audience) and replay protection.
"""

from __future__ import annotations

import base64
import secrets
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib.parse import urlencode
from xml.etree import ElementTree as ET

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
    entity_id: str                 # SP EntityID (this EMS)
    acs_url: str                   # Assertion Consumer Service URL


@dataclass(slots=True)
class IdpConfig:
    entity_id: str                 # IdP EntityID
    sso_url: str                   # IdP SingleSignOnService (HTTP-Redirect)
    certificate: Optional[str] = None  # IdP signing cert (PEM body), if known


@dataclass(slots=True)
class SamlAssertion:
    name_id: str
    attributes: dict[str, list[str]] = field(default_factory=dict)
    session_index: Optional[str] = None


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
        {"Binding": BIND_POST, "Location": sp.acs_url, "index": "0", "isDefault": "true"},
    )
    return ET.tostring(ed, encoding="unicode")


# --- AuthnRequest (SP -> IdP, HTTP-Redirect) ----------------------------

def build_authn_request(
    sp: SpConfig, idp: IdpConfig, *, relay_state: Optional[str] = None
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
    verify_signature: Optional[Callable[[bytes], bool]] = None,
    require_signature: bool = False,
) -> SamlAssertion:
    try:
        xml_bytes = base64.b64decode(saml_response_b64)
    except (ValueError, TypeError) as err:
        raise SamlError("SAMLResponse is not valid base64") from err

    if require_signature:
        if verify_signature is None or not verify_signature(xml_bytes):
            raise SamlError("SAMLResponse signature could not be verified")

    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as err:
        raise SamlError("SAMLResponse is not well-formed XML") from err

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
    for attr in assertion.findall(
        f"{{{SAML}}}AttributeStatement/{{{SAML}}}Attribute"
    ):
        name = attr.get("Name", "")
        values = [
            (v.text or "")
            for v in attr.findall(f"{{{SAML}}}AttributeValue")
        ]
        if name:
            attributes[name] = values

    authn = assertion.find(f"{{{SAML}}}AuthnStatement")
    session_index = authn.get("SessionIndex") if authn is not None else None

    return SamlAssertion(name_id=name_id, attributes=attributes, session_index=session_index)


# --- IdP metadata import ------------------------------------------------

def parse_idp_metadata(xml_text: str) -> IdpConfig:
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

    cert_el = idp_desc.find(
        f"{{{MD}}}KeyDescriptor//{{{DS}}}X509Certificate"
    )
    certificate = (cert_el.text or "").strip() if cert_el is not None else None

    return IdpConfig(entity_id=entity_id, sso_url=sso.get("Location"), certificate=certificate)


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

    def __init__(self, base_url: str, *, require_signature: bool = False) -> None:
        self._base_url = base_url.rstrip("/")
        self._require_signature = require_signature
        self._idps: dict[str, IdpConfig] = {}

    def sp_config(self, prefix: str) -> SpConfig:
        return SpConfig(
            entity_id=f"{self._base_url}/fct_saml/{prefix}/metadata",
            acs_url=f"{self._base_url}/fct_saml/{prefix}/acs",
        )

    def register_idp(self, prefix: str, idp: IdpConfig) -> None:
        self._idps[prefix] = idp

    def register_idp_from_metadata(self, prefix: str, metadata_xml: str) -> IdpConfig:
        idp = parse_idp_metadata(metadata_xml)
        self._idps[prefix] = idp
        return idp

    def _idp(self, prefix: str) -> IdpConfig:
        idp = self._idps.get(prefix)
        if idp is None:
            raise UnknownIdpError(prefix)
        return idp

    def metadata(self, prefix: str) -> str:
        return build_sp_metadata(self.sp_config(prefix))

    def login_redirect(self, prefix: str, *, relay_state: Optional[str] = None) -> str:
        _, url = build_authn_request(
            self.sp_config(prefix), self._idp(prefix), relay_state=relay_state
        )
        return url

    def consume(self, prefix: str, saml_response_b64: str) -> SamlAssertion:
        idp = self._idp(prefix)  # ensure the tenant exists before trusting a response
        verifier: Optional[Callable[[bytes], bool]] = None
        if self._require_signature and idp.certificate:
            from .saml_signatures import certificate_to_pem, make_signxml_verifier

            verifier = make_signxml_verifier(certificate_to_pem(idp.certificate))
        return parse_saml_response(
            saml_response_b64,
            verify_signature=verifier,
            require_signature=self._require_signature,
        )
