# Browser visibility contract

Status: staged extension implementation; native broker and real-browser deployment acceptance are separate work. Approved as part of the web-filter visibility plan on 2026-10-27.

## Scope and collection boundary

- Observe `webNavigation.onCommitted` for active, top-level public HTTP(S) documents only. A committed document is not proof that a person read a page.
- Collection is disabled by default. A visible extension popup controls enablement and optional path collection. Store only these booleans; never persist navigation history or unsent observations.
- Exclude private/incognito contexts, subframes, prerender/cached documents, internal browser schemes, credentials in URLs, loopback/private IPs and local/intranet hostnames. No content scripts, page title, cookies, forms, request bodies, history backfill or browser-account identity.
- Default observation is an origin. URL paths require explicit extension opt-in and native policy permission. Query strings, fragments and user information are never sent. Paths can still contain sensitive information; leave them disabled unless operationally required.
- No listening HTTP endpoint, remote collector URL or endpoint token lives in the extension.

## Native messaging, protocol 1

Host name: `com.openems.browser`. The native host installer must pin exact extension IDs: Chrome `allowed_origins` has no wildcards; Firefox uses `allowed_extensions`. Browser-side host selection is not a substitute for native-side caller validation and a protected broker installation.

1. Extension sends `hello` with `protocol: 1` and its version. No navigation data is present.
2. Native host replies `ready` with `protocol: 1`, `session_id` and `policy_digest` (64 lowercase hexadecimal characters each), `enabled: true` and `url_mode: "origin" | "path"`.
3. For each eligible navigation, the extension first sends `decide` with a random `request_id`, the current session/digest and normalized `domain` only. The broker must evaluate current policy without logging this lookup as navigation or forwarding allowed lookups to the server.
4. Native host replies `decision` matching the request/session/digest/domain, with `action: "allow" | "block" | "monitor"`. Only `monitor` may authorize a separate observation. An optional category is informational and must be a bounded identifier.
5. The extension sends `observation` with its random ID, matching session/digest/domain, UTC `observed_at`, `source: "browser"`, `kind: "committed_navigation"`, and sanitized `url`. No observation is sent for `allow` or `block`; DNS block telemetry remains independent.

The broker must re-evaluate the current policy before accepting an observation: a decision may become stale during navigation. It must validate size/schema, reject callers outside the allowlist, rate-limit messages, enforce retention/access rules and make replay/idempotency handling explicit. A browser observation is a separate source from DNS; it must not inflate block counts or be presented as device-wide visibility.

## Failure and resource behavior

- Before valid pairing, no hostname lookup or observation is sent. An absent host, invalid handshake, timeout or disconnect keeps collection inactive.
- Request lifetime is bounded; at most 32 policy decisions may be pending. When the limit is reached, new observations are dropped with an in-memory counter, never queued to disk.
- Opt-out, policy revision change, disconnect and malformed native replies invalidate pending decisions. Late replies cannot resurrect collection or use a prior session.
- A failed native connection is retried only on explicit enable/reconnect or a later eligible event. No infinite retry loop or replay of old navigation is allowed.
- Extension event handlers and popup errors must report fixed status codes/messages, never raw navigation URLs.

## Browser targets

Chrome Manifest V3 uses a module service worker. Firefox Manifest V3 uses module background scripts and a fixed Gecko ID. A build step emits separate manifests; it does not modify the installed browsers, register a native host, install the extension or grant private-browsing access.

## Verification

Node tests use mocked extension APIs to prove opt-in, handshake, host-only policy lookup, allow suppression, URL minimization, excluded contexts, bounded pending work, timeouts and stale replies. Build contracts inspect both manifests and native-host templates. A fixture is not acceptance of the Rust agent broker, Chrome Web Store/AMO distribution, signed packages, a physical endpoint, or server persistence.

Primary API references, checked 2026-10-27:

- [Chrome Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
- [MDN native messaging](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging)
- [MDN onCommitted](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webNavigation/onCommitted)
- [MDN cross-browser background contexts](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/background)
