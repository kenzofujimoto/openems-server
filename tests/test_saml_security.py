"""Security regressions for SAML trust, correlation and shared storage."""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from app.saml import IdpConfig, SamlError, SamlSp, parse_saml_response


def test_default_parser_refuses_unsigned_response() -> None:
    xml = ('<p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" '
           'xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion">'
           '<p:Status><p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
           '</p:Status><s:Assertion><s:Subject><s:NameID>attacker</s:NameID>'
           '</s:Subject></s:Assertion></p:Response>')
    with pytest.raises(SamlError, match="signature"):
        parse_saml_response(base64.b64encode(xml.encode()).decode())


def test_idp_store_survives_sp_recreation() -> None:
    from app.idp_store import InMemoryIdpStore

    store = InMemoryIdpStore()
    first = SamlSp("https://ems.example", idp_store=store)
    idp = IdpConfig("https://idp.example", "https://idp.example/sso", "certificate")
    first.register_idp("acme", idp)
    second = SamlSp("https://ems.example", idp_store=store)
    assert second.login_redirect("acme").startswith(idp.sso_url)


def test_pending_request_is_bound_and_atomically_consumed() -> None:
    from app.replay import InMemoryPendingRequestStore

    store = InMemoryPendingRequestStore()
    store.put("request", "acme", "opaque", datetime.now(timezone.utc) + timedelta(minutes=1))
    assert not store.consume("request", "other", "opaque")
    assert not store.consume("request", "acme", "wrong")
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: store.consume("request", "acme", "opaque"), range(20)))
    assert results.count(True) == 1


def test_pending_request_expiry_is_enforced() -> None:
    from app.replay import InMemoryPendingRequestStore

    store = InMemoryPendingRequestStore()
    store.put("expired", "acme", None, datetime.now(timezone.utc) - timedelta(seconds=1))
    assert not store.consume("expired", "acme", None)


@pytest.fixture(scope="module")
def signing_material():
    pytest.importorskip("signxml")
    from test_saml_signature import _make_cert
    return _make_cert()


@pytest.fixture
def secure_exchange(signing_material):
    import zlib
    from urllib.parse import parse_qs, urlparse
    from xml.etree import ElementTree as ET
    from app.saml import SAMLP
    from test_saml_signature import _sign

    key, cert, der = signing_material
    sp = SamlSp("https://ems.example")
    sp.register_idp("acme", IdpConfig("https://idp.example", "https://idp.example/sso", der))
    query = parse_qs(urlparse(sp.login_redirect("acme", relay_state="state")).query)
    request = ET.fromstring(zlib.decompress(base64.b64decode(query["SAMLRequest"][0]), -15))
    request_id = request.get("ID")
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    xml = f'''<p:Response xmlns:p="{SAMLP}" xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="_response" Destination="https://ems.example/fct_saml/acme/acs" InResponseTo="{request_id}">
      <s:Issuer>https://idp.example</s:Issuer>
      <p:Status><p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></p:Status>
      <s:Assertion ID="_assertion"><s:Issuer>https://idp.example</s:Issuer>
        <s:Subject><s:NameID>alice@example.com</s:NameID>
          <s:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <s:SubjectConfirmationData Recipient="https://ems.example/fct_saml/acme/acs"
             InResponseTo="{request_id}" NotOnOrAfter="{expiry}"/>
          </s:SubjectConfirmation>
        </s:Subject>
        <s:Conditions NotOnOrAfter="{expiry}"><s:AudienceRestriction>
          <s:Audience>https://ems.example/fct_saml/acme/metadata</s:Audience>
        </s:AudienceRestriction></s:Conditions>
      </s:Assertion>
    </p:Response>'''
    def encode(value):
        return base64.b64encode(_sign(value, key, cert)).decode()
    return sp, xml, encode


def test_secure_exchange_single_use_and_state(secure_exchange):
    sp, xml, encode = secure_exchange
    response = encode(xml)
    with pytest.raises(SamlError, match="outstanding"):
        sp.consume("acme", response, relay_state="wrong")
    assert sp.consume("acme", response, relay_state="state").name_id == "alice@example.com"
    with pytest.raises(SamlError):
        sp.consume("acme", response, relay_state="state")


@pytest.mark.parametrize("old,new", [
    ('https://idp.example</s:Issuer>', 'https://evil.example</s:Issuer>'),
    ('Destination="https://ems.example/fct_saml/acme/acs"', 'Destination="https://evil.example"'),
    ('Recipient="https://ems.example/fct_saml/acme/acs"', 'Recipient="https://evil.example"'),
    ('<s:Audience>https://ems.example/fct_saml/acme/metadata</s:Audience>', ''),
    ('ID="_assertion"', ''),
    ('ID="_response"', ''),
    ('NotOnOrAfter="', 'NotOnOrAfter="invalid'),
    ('InResponseTo="', 'InResponseTo="unrequested'),
])
def test_signed_but_invalid_binding_rejected(secure_exchange, old, new):
    sp, xml, encode = secure_exchange
    with pytest.raises(SamlError):
        sp.consume("acme", encode(xml.replace(old, new)), relay_state="state")


def test_multiple_assertions_rejected_even_when_signed(secure_exchange):
    sp, xml, encode = secure_exchange
    xml = xml.replace('</p:Response>', '<s:Assertion ID="_extra"/></p:Response>')
    with pytest.raises(SamlError, match="exactly one"):
        sp.consume("acme", encode(xml), relay_state="state")


def test_invalid_signature_does_not_consume_pending_request(secure_exchange):
    sp, xml, encode = secure_exchange
    response = encode(xml)
    tampered = base64.b64decode(response).replace(b"alice@example.com", b"evil@example.com")
    with pytest.raises(SamlError, match="signature"):
        sp.consume("acme", base64.b64encode(tampered).decode(), relay_state="state")
    assert sp.consume("acme", response, relay_state="state").name_id == "alice@example.com"


def test_verified_node_is_consumed_instead_of_original_document(signing_material):
    from xml.etree import ElementTree as ET
    from test_saml_signature import RESPONSE
    trusted = ET.fromstring(RESPONSE.replace("carol@example.com", "trusted@example.com"))
    result = parse_saml_response(base64.b64encode(RESPONSE.encode()).decode(),
                                verify_signature=lambda _: trusted)
    assert result.name_id == "trusted@example.com"


def test_boolean_signature_hook_is_rejected(signing_material):
    from test_saml_signature import RESPONSE
    with pytest.raises(SamlError, match="signature"):
        parse_saml_response(base64.b64encode(RESPONSE.encode()).decode(), verify_signature=lambda _: True)


def test_assertion_signature_cannot_replace_signed_response(signing_material):
    from test_saml_signature import _sign
    from app.saml_signatures import make_signxml_verifier
    key, cert, _ = signing_material
    assertion = '<s:Assertion xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion"/>'
    assert make_signxml_verifier(cert.decode())(_sign(assertion, key, cert)) is None


def test_signature_wrapping_rejected(secure_exchange):
    from xml.etree import ElementTree as ET
    sp, xml, encode = secure_exchange
    signed = base64.b64decode(encode(xml)).decode()
    wrapper = ('<p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_outer">'
               + signed + '</p:Response>')
    with pytest.raises(SamlError, match="signature"):
        sp.consume("acme", base64.b64encode(wrapper.encode()).decode(), relay_state="state")


def test_concurrent_response_consumption_succeeds_once(secure_exchange):
    sp, xml, encode = secure_exchange
    response = encode(xml)
    def attempt(_):
        try:
            sp.consume("acme", response, relay_state="state")
            return True
        except SamlError:
            return False
    with ThreadPoolExecutor(max_workers=8) as executor:
        assert list(executor.map(attempt, range(12))).count(True) == 1


def test_replay_cache_retains_complete_skew_window(secure_exchange):
    sp, xml, encode = secure_exchange
    now = datetime.now(timezone.utc)
    from xml.etree import ElementTree as ET
    root = ET.fromstring(xml)
    for element in root.iter():
        if element.get("NotOnOrAfter"):
            element.set("NotOnOrAfter", (now - timedelta(seconds=30)).isoformat())
    assert sp.consume("acme", encode(ET.tostring(root).decode()), relay_state="state", now=now)
    values = list(sp._replay_cache._seen.values())
    assert len(values) == 1
    assert values[0] == now + timedelta(seconds=30)


@pytest.mark.parametrize("mutation", ["assertion_expiry", "subject_expiry", "subject_expired", "request_mismatch", "confirmation", "duplicate_confirmation", "duplicate_ids", "naive_date"])
def test_required_protocol_fields(secure_exchange, mutation):
    from xml.etree import ElementTree as ET
    from app.saml import SAML
    sp, xml, encode = secure_exchange
    root = ET.fromstring(xml)
    assertion = root.find(f"{{{SAML}}}Assertion")
    conditions = assertion.find(f"{{{SAML}}}Conditions")
    subject = assertion.find(f"{{{SAML}}}Subject")
    confirmation = subject.find(f"{{{SAML}}}SubjectConfirmation")
    data = confirmation.find(f"{{{SAML}}}SubjectConfirmationData")
    if mutation == "assertion_expiry":
        del conditions.attrib["NotOnOrAfter"]
    elif mutation == "subject_expiry":
        del data.attrib["NotOnOrAfter"]
    elif mutation == "subject_expired":
        data.set("NotOnOrAfter", (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat())
    elif mutation == "request_mismatch":
        data.set("InResponseTo", "_other")
    elif mutation == "confirmation":
        confirmation.set("Method", "unknown")
    elif mutation == "duplicate_confirmation":
        subject.append(ET.fromstring(ET.tostring(confirmation)))
    elif mutation == "duplicate_ids":
        assertion.set("ID", root.get("ID"))
    else:
        conditions.set("NotOnOrAfter", "2026-10-22T12:00:00")
    with pytest.raises(SamlError):
        sp.consume("acme", encode(ET.tostring(root).decode()), relay_state="state")


@pytest.mark.parametrize("payload", ["<broken", "<other/>", '<!DOCTYPE data [<!ENTITY secret "secret">]><data/>'])
def test_untrusted_xml_is_rejected(payload):
    with pytest.raises(SamlError):
        parse_saml_response(base64.b64encode(payload.encode()).decode(), require_signature=False)


def test_certificate_optional_only_in_explicit_lab_mode():
    idp = IdpConfig("https://idp.example", "https://idp.example/sso")
    with pytest.raises(SamlError, match="certificate"):
        SamlSp("https://ems.example").register_idp("acme", idp)
    with pytest.raises(SamlError, match="certificate"):
        SamlSp("https://ems.example").register_idp_from_metadata("acme", '''<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="idp"><IDPSSODescriptor><SingleSignOnService Location="https://idp.example/sso"/></IDPSSODescriptor></EntityDescriptor>''')


@pytest.mark.parametrize("kwargs", [{"clock_skew_seconds": -1}, {"request_ttl_seconds": 0}])
def test_invalid_saml_timing_config(kwargs):
    with pytest.raises(ValueError):
        SamlSp("https://ems.example", **kwargs)


def test_idp_store_does_not_expose_mutable_config():
    from app.idp_store import InMemoryIdpStore
    store = InMemoryIdpStore()
    configured = IdpConfig("trusted", "https://idp.example/sso", "cert")
    store.put("a", configured)
    configured.entity_id = "evil"
    saved = store.get("a")
    assert saved.entity_id == "trusted"
    saved.entity_id = "evil"
    assert store.get("a").entity_id == "trusted"
    assert store.get("unknown") is None


def test_pem_certificate_passthrough(signing_material):
    from app.saml_signatures import certificate_to_pem
    _, cert, der = signing_material
    assert certificate_to_pem(cert.decode()) == cert.decode()
    assert certificate_to_pem(der) == cert.decode()


def test_parser_rejects_oversize_before_decode(monkeypatch):
    def forbid_decode(*args, **kwargs):
        raise AssertionError("Oversized data must not be decoded")
    monkeypatch.setattr("app.saml.base64.b64decode", forbid_decode)
    with pytest.raises(SamlError, match="size"):
        parse_saml_response("A" * 1_400_001)


def test_shared_redis_pending_and_replay_contract():
    import os
    from uuid import uuid4
    from app.replay import RedisPendingRequestStore, RedisReplayCache
    url = os.environ.get("OPENEMS_TEST_REDIS")
    if not url:
        pytest.skip("OPENEMS_TEST_REDIS required")
    namespace = f"test-saml-{uuid4()}:"
    pending = RedisPendingRequestStore(url, prefix=namespace + "pending:")
    worker = RedisPendingRequestStore(url, prefix=namespace + "pending:")
    replay = RedisReplayCache(url, prefix=namespace + "replay:")
    other = RedisReplayCache(url, prefix=namespace + "replay:")
    future = datetime.now(timezone.utc) + timedelta(minutes=1)
    try:
        pending.put("req", "acme", "state", future)
        assert not worker.consume("req", "other", "state")
        assert not worker.consume("req", "acme", None)
        assert worker.consume("req", "acme", "state")
        assert not pending.consume("req", "acme", "state")
        pending.put("duplicate", "acme", None, future)
        with pytest.raises(ValueError, match="Duplicate"):
            worker.put("duplicate", "acme", None, future)
        with pytest.raises(ValueError, match="expiry"):
            pending.put("past", "acme", None, datetime.now(timezone.utc) - timedelta(seconds=1))
        assert replay.check_and_remember("assertion", future)
        assert not other.check_and_remember("assertion", future)
        assert not replay.check_and_remember("expired", datetime.now(timezone.utc) - timedelta(seconds=1))
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _: other.check_and_remember("race", future), range(12)))
        assert results.count(True) == 1
        near = datetime.now(timezone.utc) + timedelta(seconds=1.9)
        assert replay.check_and_remember("skew", near)
        assert replay._redis.ttl(namespace + "replay:skew") == 2
    finally:
        keys = list(pending._redis.scan_iter(match=namespace + "*"))
        if keys:
            pending._redis.delete(*keys)


def test_postgres_idp_store_persists_trust_across_connections():
    import os
    from uuid import uuid4
    from app.idp_store import PostgresIdpStore
    dsn = os.environ.get("OPENEMS_TEST_DSN")
    if not dsn:
        pytest.skip("OPENEMS_TEST_DSN required")
    first = PostgresIdpStore(dsn)
    second = PostgresIdpStore(dsn)
    first.init_schema()
    prefix = f"test-{uuid4()}"
    try:
        assert second.get(prefix) is None
        first.put(prefix, IdpConfig("initial", "https://idp.example/sso", "old-cert"))
        assert second.get(prefix).certificate == "old-cert"
        first.put(prefix, IdpConfig("updated", "https://new.example/sso", "new-cert"))
        saved = second.get(prefix)
        assert (saved.entity_id, saved.sso_url, saved.certificate) == ("updated", "https://new.example/sso", "new-cert")
    finally:
        first._conn.execute("DELETE FROM saml_idps WHERE prefix=%s", (prefix,))
        first._conn.close()
        second._conn.close()


@pytest.mark.parametrize("xml", ["<broken", "<other/>", '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="idp"><IDPSSODescriptor/></EntityDescriptor>'])
def test_malformed_metadata_rejected(xml):
    from app.saml import parse_idp_metadata
    with pytest.raises(SamlError):
        parse_idp_metadata(xml)


def test_metadata_with_dtd_rejected():
    from app.saml import parse_idp_metadata
    xml = '''<!DOCTYPE EntityDescriptor [<!ENTITY issuer "https://idp.example">]>
    <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="&issuer;">
    <IDPSSODescriptor><SingleSignOnService Location="https://idp.example/sso"/></IDPSSODescriptor>
    </EntityDescriptor>'''
    with pytest.raises(SamlError, match="DTD"):
        parse_idp_metadata(xml)


def test_parser_rejects_missing_subject_and_non_direct_assertion():
    from test_saml_signature import RESPONSE
    for xml in [RESPONSE.replace("carol@example.com", ""), RESPONSE.replace("<saml:Assertion>", "<wrapper><saml:Assertion>").replace("</saml:Assertion>", "</saml:Assertion></wrapper>")]:
        with pytest.raises(SamlError):
            parse_saml_response(base64.b64encode(xml.encode()).decode(), require_signature=False)
