"""XML-DSig signature verification for SAML responses (signxml-based).

Kept separate from saml.py so the core SAML message handling has no heavy crypto
dependency; this module is imported only when signature enforcement is enabled.

`make_signxml_verifier(cert_pem)` returns a callable suitable for
`parse_saml_response(verify_signature=...)`: it returns True only if the XML
carries a valid enveloped signature made by the key matching `cert_pem`, and
fails closed (returns False) on any error.
"""

from __future__ import annotations

from typing import Callable


def certificate_to_pem(cert_b64: str) -> str:
    """Wrap a bare base64 DER certificate (as found in SAML metadata) in PEM."""
    body = "".join(cert_b64.split())
    wrapped = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----\n"


def make_signxml_verifier(cert_pem: str) -> Callable[[bytes], bool]:
    """Build a fail-closed verifier bound to one trusted certificate."""
    from signxml import XMLVerifier  # lazy: only needed when enforcing signatures

    verifier = XMLVerifier()

    def verify(xml_bytes: bytes) -> bool:
        try:
            verifier.verify(xml_bytes, x509_cert=cert_pem)
            return True
        except Exception:
            # Any failure — bad signature, wrong cert, malformed XML — is a reject.
            return False

    return verify
