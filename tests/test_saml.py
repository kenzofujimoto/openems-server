"""Tests for the clean-room SAML 2.0 SP core (app/saml.py)."""

from __future__ import annotations

import base64
from urllib.parse import parse_qs, urlparse

import pytest

from app.saml import (
    IdpConfig,
    SamlError,
    SamlSp,
    SpConfig,
    build_authn_request,
    build_sp_metadata,
    parse_idp_metadata,
    parse_saml_response,
)

SP = SpConfig(entity_id="https://ems.example/sp", acs_url="https://ems.example/acs")
IDP = IdpConfig(entity_id="https://idp.example", sso_url="https://idp.example/sso")


def _b64(xml: str) -> str:
    return base64.b64encode(xml.encode("utf-8")).decode("ascii")


def _response_xml(status: str, name_id: str = "alice@example.com") -> str:
    return f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
      <samlp:Status><samlp:StatusCode Value="{status}"/></samlp:Status>
      <saml:Assertion>
        <saml:Subject><saml:NameID>{name_id}</saml:NameID></saml:Subject>
        <saml:AuthnStatement SessionIndex="sess-123"/>
        <saml:AttributeStatement>
          <saml:Attribute Name="groups">
            <saml:AttributeValue>admins</saml:AttributeValue>
            <saml:AttributeValue>vpn</saml:AttributeValue>
          </saml:Attribute>
        </saml:AttributeStatement>
      </saml:Assertion>
    </samlp:Response>"""


IDP_METADATA = """<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
      xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example">
    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data>
        <ds:X509Certificate>ABC123CERT</ds:X509Certificate>
      </ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
      <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://idp.example/sso"/>
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>"""


def test_sp_metadata_contains_entity_and_acs() -> None:
    xml = build_sp_metadata(SP)
    assert SP.entity_id in xml
    assert SP.acs_url in xml
    assert "SPSSODescriptor" in xml


def test_authn_request_redirect_carries_samlrequest() -> None:
    _, url = build_authn_request(SP, IDP, relay_state="back-here")
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    assert parsed.scheme + "://" + parsed.netloc + parsed.path == IDP.sso_url
    assert "SAMLRequest" in qs
    assert qs["RelayState"] == ["back-here"]


def test_parse_success_response_extracts_nameid_and_attributes() -> None:
    assertion = parse_saml_response(_b64(_response_xml(
        "urn:oasis:names:tc:SAML:2.0:status:Success"
    )))
    assert assertion.name_id == "alice@example.com"
    assert assertion.attributes["groups"] == ["admins", "vpn"]
    assert assertion.session_index == "sess-123"


def test_parse_non_success_status_raises() -> None:
    with pytest.raises(SamlError):
        parse_saml_response(_b64(_response_xml(
            "urn:oasis:names:tc:SAML:2.0:status:Responder"
        )))


def test_parse_rejects_bad_base64() -> None:
    with pytest.raises(SamlError):
        parse_saml_response("!!!not-base64!!!")


def test_require_signature_without_verifier_raises() -> None:
    with pytest.raises(SamlError):
        parse_saml_response(
            _b64(_response_xml("urn:oasis:names:tc:SAML:2.0:status:Success")),
            require_signature=True,
        )


def test_parse_idp_metadata() -> None:
    idp = parse_idp_metadata(IDP_METADATA)
    assert idp.entity_id == "https://idp.example"
    assert idp.sso_url == "https://idp.example/sso"
    assert idp.certificate == "ABC123CERT"


def test_sp_registers_idp_from_metadata_and_builds_login() -> None:
    sp = SamlSp("https://ems.example")
    sp.register_idp_from_metadata("acme", IDP_METADATA)
    url = sp.login_redirect("acme")
    assert url.startswith("https://idp.example/sso?")


def test_sp_consume_unknown_prefix_raises() -> None:
    sp = SamlSp("https://ems.example")
    with pytest.raises(SamlError):
        sp.consume("ghost", _b64(_response_xml(
            "urn:oasis:names:tc:SAML:2.0:status:Success"
        )))
