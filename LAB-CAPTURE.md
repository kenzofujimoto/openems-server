# Lab capture guide — fixing the 8013 endpoint-channel payloads

Goal: turn the `[a capturar]` items in [`../SPEC-INTEROP.md`](../SPEC-INTEROP.md)
(exact register/refresh/keepalive/avatar/host_tags bodies, serialization,
keepalive cadence, auth scheme, TLS pinning) into **observed facts**, then tighten
this server's request models and tests.

> **Scope / legal.** Do this **only** against a lab EMS and endpoints you own or
> are authorized to operate, on an isolated network. Capture your own traffic for
> interoperability — never production, never someone else's deployment. Do not
> extract or redistribute the vendor's code; you are documenting an interface.

There are two strategies. **A** is the cleanest and needs no TLS-interception; use
**B** when you also want to see the *real EMS's responses*.

---

## Strategy A — point a lab endpoint at openems-server and record (recommended)

The server terminates TLS itself, so the endpoint's requests arrive in cleartext
and are written to a JSONL file by the recorder (`app/recording.py`). No
certificate-pinning fight, no decryption.

1. **Make a TLS cert the lab endpoint will accept.** FortiClient-style agents talk
   HTTPS to the EMS and validate the cert, so either install this cert's CA on the
   endpoint host, or use a lab endpoint configured to accept it.
   ```bash
   openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem \
     -days 365 -subj "/CN=ems.lab.local"
   ```

2. **Run the server with recording on, over TLS, on 8013:**
   ```bash
   OPENEMS_RECORD=capture.jsonl \
   python -m uvicorn --factory app.api:build --host 0.0.0.0 --port 8013 \
     --ssl-keyfile key.pem --ssl-certfile cert.pem
   ```

3. **Point the lab endpoint at it.** Register the endpoint to EMS address
   `ems.lab.local` (map that name to the server's IP via the endpoint's hosts file),
   port 8013. Trigger register, then let it run so keepalive/telemetry fire.

4. **Analyze the capture:**
   ```bash
   python tools/analyze_capture.py capture.jsonl
   ```
   You get, per path: request count, content-type, the union of JSON body keys,
   and a sample body — exactly what the spec's `[a capturar]` fields need.

What this nails down: the real paths and **bodies** of `register`/`refresh`/
`update_client_id` and whatever telemetry/keepalive calls the endpoint makes, the
**serialization** (is it JSON? form? protobuf?), the **auth** fields (invitation,
key, tokens), and — from the timestamps between requests — the **keepalive cadence**.

---

## Strategy B — MITM the real lab EMS with mitmproxy

Use when you want the real EMS's **responses** too (config push shape, error codes).

1. Install mitmproxy (`pipx install mitmproxy`) and start it, writing flows out:
   ```bash
   mitmdump -w flows.mitm --mode reverse:https://ems.lab.local:8013 --listen-port 8013
   ```
   (Or transparent mode with routing; reverse mode is simplest for one host.)

2. **Trust the mitmproxy CA on the endpoint host** (`~/.mitmproxy/mitmproxy-ca-cert.cer`)
   and redirect the EMS hostname to the mitmproxy box (endpoint hosts file →
   `ems.lab.local` = mitmproxy IP).

3. Exercise the endpoint (register, wait for keepalives).

4. Export and inspect. mitmproxy can export a flow to JSON/HAR; a tiny script can
   reshape a flow dump into the same JSONL this repo's analyzer reads (one object
   per request with `method`/`path`/`body_text`).

> **Pinning caveat.** FortiClient may pin the EMS certificate, in which case the
> TLS handshake through mitmproxy fails and the endpoint refuses to register. If
> that happens, fall back to **Strategy A** (you control the cert there), or read
> the EMS-side request logs, or the endpoint-side diagnostic logs.

---

## Feeding results back into the project

For each `[a capturar]` item the capture resolves:

1. Update the matching table/section in `SPEC-INTEROP.md` (§2.2–2.5), replacing
   `[a capturar]` with the observed fact and citing it as `[obs]`.
2. Tighten the request models — e.g. turn `RegisterRequest` / the ad-hoc dict
   payloads in `app/api.py` into precise Pydantic models with the real field names
   and types; add the real keepalive/avatar routes.
3. Add a request-shape test that posts a *recorded* body and asserts the server
   accepts it (regression against the real wire format).

This is the loop that moves openems-server from "protocol-compatible by design"
to "protocol-compatible, verified against a real endpoint."
