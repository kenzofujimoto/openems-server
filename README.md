# openems-server

A **clean-room, open-source** endpoint-management server that aims to be
*protocol-compatible* with FortiClient-style endpoint agents, so endpoints can
register, send posture/telemetry, and be managed by a free server.

> **Provenance / legal.** This project is written **only** from the behavioural
> interoperability specification in [`../SPEC-INTEROP.md`](../SPEC-INTEROP.md),
> which documents an *observed interface* (endpoints, fields, sequences). No
> proprietary Fortinet code, binary, or asset is copied here, and the names
> "Fortinet"/"FortiClient" are not used as product branding. Reverse engineering
> for interoperability is treated differently across jurisdictions and EULAs —
> validate with a lawyer before distributing. Not affiliated with Fortinet.

## What works today
- `EmsService` core (no web deps): register / refresh / update_client_id,
  host-tag ingestion, endpoint listing — fully unit-tested.
- Storage: `InMemoryStore` (default) and `PostgresStore` (psycopg 3), both held to
  one contract test suite. The Postgres contract tests run when `OPENEMS_TEST_DSN`
  points at a database (otherwise skipped).
- Queue: `InMemoryQueue` (default) and `RedisQueue` (redis-py), same contract-test
  pattern (`OPENEMS_TEST_REDIS`). Used for config/profile push notifications.
- **Config/profile push:** an admin publishes a per-vdom profile; the service bumps
  a version and enqueues a `config_update` per endpoint in that vdom; the endpoint
  drains its queue, fetches the config, and acks the applied version. Profiles are
  held by a `ProfileStore` — `InMemoryProfileStore` or `PostgresProfileStore`
  (same contract test pattern as the endpoint store).
- **SAML 2.0 SP** (`app/saml.py`, clean-room implementation of the OASIS standard):
  SP metadata, AuthnRequest (HTTP-Redirect), SAMLResponse parsing at the ACS
  (HTTP-POST), multi-tenant IdP registry keyed by URL prefix.
- **SAML signature verification** (`app/saml_signatures.py`, signxml): with
  `SamlSp(require_signature=True)` the ACS verifies the response's enveloped
  XML-DSig against the registered IdP certificate and fails closed. Tested
  end-to-end (valid → accept, tampered → reject, wrong cert → reject).
- **SAML assertion conditions + replay protection**: the ACS enforces the
  `NotBefore`/`NotOnOrAfter` window (with clock-skew tolerance) and the
  `AudienceRestriction`, and rejects a reused assertion ID via a `ReplayCache`
  (`app/replay.py`: `InMemoryReplayCache`, or `RedisReplayCache` using
  `SET NX EX`).
- **Group assignment rules** (`app/rules.py`): priority-ordered rules with
  conditions (`os`/`hostname`/`fctver`/`vdom`/`host_tag`, ops
  `equals`/`contains`/`in`/`has_tag`, all AND-ed) decide an endpoint's effective
  vdom/profile. Config push targets each endpoint by its *effective* vdom, so a
  rule can move an endpoint to a different policy than it registered under.
  Endpoint fetches its assigned config by client_id.
- **Traffic recorder** (`app/recording.py`): an ASGI middleware that tees every
  endpoint-channel request body to a JSONL file (enable with `record_path=` or
  `OPENEMS_RECORD=`), replaying it downstream so routes still work and redacting
  sensitive headers. Point a lab endpoint at the server and capture its real wire
  format in cleartext — no TLS interception. `tools/analyze_capture.py` summarizes
  the capture (paths, JSON keys, sample bodies). See
  [`../LAB-CAPTURE.md`](../LAB-CAPTURE.md).
- **Admin authentication** (`app/auth.py`): PBKDF2-SHA256 password hashing and
  stateless HMAC-signed bearer tokens. A middleware gates every `/api/v1/*` route
  (except `/api/v1/auth/login`) once any admin exists — until then it runs in open
  *setup mode*. The endpoint channel (`/fct/api/*`) keeps its own device auth and
  is never gated. The console has a sign-in overlay (token in `localStorage`,
  attached to every call, 401 → re-login). Bootstrap an admin with
  `OPENEMS_ADMIN=user:pass`.
- **Audit log** (`app/audit.py`): every mutating admin action (profile.publish,
  rule.add, rule.remove) is recorded with the acting admin (from the verified
  token), timestamp, target and metadata — `InMemoryAuditLog` or
  `PostgresAuditLog`. Served at `GET /api/v1/audit` and shown in the console.
- **94 tests pass**, 13 skipped (Postgres + Redis without a live server).
- FastAPI HTTP layer exposing:
  - endpoint channel: `POST /fct/api/public/v1/register|refresh|update_client_id/`,
    `POST /fct/api/public/v1/messages/pull/`, `GET /fct/api/public/v1/config/`,
    `POST /fct/api/public/v1/config/ack/`
    plus `GET /fct/api/public/v1/config/assigned/?client_id=...`
  - management: `GET /api/v1/endpoints/index|count`,
    `GET /api/v1/report/fct/host_tags?devid=...`, `POST /api/v1/profiles/{vdom}`,
    `POST|GET /api/v1/assignment_rules`
  - SAML: `GET /fct_saml/{prefix}/metadata`, `GET /fct_saml/login`,
    `POST /fct_saml/{prefix}/acs`, `POST /fct_saml/parse_remote_metadata`

## Not done yet (needs real traffic capture)
The **exact payloads** of the endpoint channel (serialization, keepalive cadence,
avatar chunking, the 8013 auth/TLS handshake) are marked `[a capturar]` in the
spec. Close them by capturing traffic against a lab EMS you are entitled to run,
then tighten the request/response models here. Until then the bodies above use a
pragmatic JSON shape.

## Run
```bash
python -m venv .venv && . .venv/Scripts/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn --factory app.api:build --port 8013
```

## Test
```bash
python -m pytest -q          # core + in-memory + FastAPI integration (18 pass)

# also exercise the PostgreSQL store:
docker run --rm -e POSTGRES_PASSWORD=pw -p 5432:5432 postgres:16
OPENEMS_TEST_DSN=postgresql://postgres:pw@localhost:5432/postgres python -m pytest -q
```

## Roadmap
1. Capture lab traffic → fix endpoint-channel payloads.
2. ~~Postgres store~~ ✓ · ~~Redis queue~~ ✓ · ~~config/profile push~~ ✓ · ~~SAML SP + signature + conditions/replay~~ ✓ · ~~persist profiles~~ ✓ · ~~assignment rules~~ ✓
3. ~~Web console~~ ✓ · ~~traffic recorder~~ ✓ · ~~admin auth~~ ✓ · ~~audit log~~ ✓ · persist rules + admins.
4. Capture real lab traffic (see LAB-CAPTURE.md) → replace the `[a capturar]`
   payloads with precise Pydantic models; add keepalive/avatar routes.
5. SubjectConfirmationData (Recipient/InResponseTo) checks; AuthnRequest↔Response correlation.

## License
MIT (see `LICENSE`). Contributions welcome.
