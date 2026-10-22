"""Pinned-certificate XML signatures, returning only the verified whole Response."""

from __future__ import annotations

from collections.abc import Callable
from xml.etree import ElementTree as ET

SAMLP_RESPONSE = "{urn:oasis:names:tc:SAML:2.0:protocol}Response"


def certificate_to_pem(cert_b64: str) -> str:
    if cert_b64.strip().startswith("-----BEGIN CERTIFICATE-----"):
        return cert_b64.strip() + "\n"
    body = "".join(cert_b64.split())
    wrapped = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----\n"


def make_signxml_verifier(cert_pem: str) -> Callable[[bytes], ET.Element | None]:
    from lxml import etree
    from signxml import SignatureConfiguration, XMLVerifier
    from signxml.exceptions import SignXMLException

    def verify(xml_bytes: bytes) -> ET.Element | None:
        try:
            result = XMLVerifier().verify(
                xml_bytes,
                x509_cert=cert_pem,
                expect_config=SignatureConfiguration(
                    location="./", expect_references=1
                ),
            )
            signed = result.signed_xml
            if signed.tag != SAMLP_RESPONSE:
                return None
            return ET.fromstring(etree.tostring(signed))
        except (SignXMLException, etree.LxmlError, ET.ParseError, ValueError, TypeError):
            # Invalid signature, malformed XML, missing crypto support: reject.
            return None

    return verify
