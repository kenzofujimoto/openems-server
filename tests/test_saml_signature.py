"""End-to-end tests for SAML signature verification.

Generates a throwaway self-signed cert, signs a SAMLResponse with signxml, and
checks the verifier accepts it, rejects tampering, and rejects a wrong cert.
Skipped if signxml/cryptography/lxml are not installed.
"""

from __future__ import annotations

import base64
import datetime

import pytest

pytest.importorskip("signxml")
pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from lxml import etree  # noqa: E402
from signxml import XMLSigner  # noqa: E402

from app.saml import IdpConfig, SamlError, SamlSp
from app.saml_signatures import certificate_to_pem, make_signxml_verifier

RESPONSE = (
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1">'
    '<samlp:Status><samlp:StatusCode '
    'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
    '<saml:Assertion><saml:Subject><saml:NameID>carol@example.com</saml:NameID>'
    '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
    '<saml:SubjectConfirmationData/></saml:SubjectConfirmation>'
    "</saml:Subject></saml:Assertion></samlp:Response>"
)


def _make_cert() -> tuple[bytes, bytes, str]:
    """Return (key_pem, cert_pem, cert_b64_der) for a fresh self-signed cert."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.example")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_b64_der = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    return key_pem, cert_pem, cert_b64_der


def _sign(xml: str, key_pem: bytes, cert_pem: bytes) -> bytes:
    root = etree.fromstring(xml.encode())
    signed = XMLSigner().sign(root, key=key_pem, cert=cert_pem)
    return etree.tostring(signed)


def test_valid_signature_verifies() -> None:
    key_pem, cert_pem, _ = _make_cert()
    signed = _sign(RESPONSE, key_pem, cert_pem)
    assert make_signxml_verifier(cert_pem.decode())(signed) is not None


def test_tampered_payload_fails() -> None:
    key_pem, cert_pem, _ = _make_cert()
    signed = _sign(RESPONSE, key_pem, cert_pem)
    tampered = signed.replace(b"carol@example.com", b"attacker@evil.com")
    assert make_signxml_verifier(cert_pem.decode())(tampered) is None


def test_wrong_certificate_fails() -> None:
    key_pem, cert_pem, _ = _make_cert()
    signed = _sign(RESPONSE, key_pem, cert_pem)
    _, other_cert_pem, _ = _make_cert()
    assert make_signxml_verifier(other_cert_pem.decode())(signed) is None


def test_samlsp_consume_requires_valid_signature() -> None:
    from app.saml import parse_saml_response
    key_pem, cert_pem, _ = _make_cert()
    signed = _sign(RESPONSE, key_pem, cert_pem)
    assertion = parse_saml_response(base64.b64encode(signed).decode(),
                                    verify_signature=make_signxml_verifier(cert_pem.decode()))
    assert assertion.name_id == "carol@example.com"
    with pytest.raises(SamlError):
        parse_saml_response(base64.b64encode(RESPONSE.encode()).decode(),
                            verify_signature=make_signxml_verifier(cert_pem.decode()))
