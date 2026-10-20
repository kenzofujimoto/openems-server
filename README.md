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
  one contract test suite. 18 tests pass; the Postgres contract tests run when
  `OPENEMS_TEST_DSN` points at a database (otherwise skipped).
- FastAPI HTTP layer exposing:
  - `POST /fct/api/public/v1/register/`
  - `POST /fct/api/public/v1/refresh/`
  - `POST /fct/api/public/v1/update_client_id/`
  - `GET  /api/v1/endpoints/index` · `GET /api/v1/endpoints/count`
  - `GET  /api/v1/report/fct/host_tags?devid=...`

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
2. ~~PostgreSQL store~~ ✓ (done) · Redis queue next.
3. Config/profile push to endpoints.
4. SAML SP (`/fct_saml/*`) and the web console.

## License
MIT (see `LICENSE`). Contributions welcome.
