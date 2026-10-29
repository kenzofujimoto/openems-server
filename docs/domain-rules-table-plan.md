# Ordered domain rules and CSV

## Approved scope

The operator approved a domain table with individual editing, CSV import/export,
simple/wildcard matching, and allow/block/monitor actions. On 2026-10-28 the
operator explicitly selected first-match ordering with move up/down controls.

Reference: [FortiClient EMS Web Filter](https://docs.fortinet.com/document/forticlient/7.4.3/ems-administration-guide/68075/web-filter).
EMS evaluates the first matching exclusion rule. This feature adopts that table
workflow for OpenEMS DNS domains; it does not implement full-URL, referrer, PCRE,
or warning-page inspection.

## Steps

1. Commit failing Python, Rust and panel behavior tests before implementation.
2. Add validated ordered `web_filter.domain_rules` records: `domain`, `type`
   (`simple`/`wildcard`) and `action` (`allow`/`block`/`monitor`). Normalize IDNA,
   preserve array order and reject ambiguous mixed legacy lists. DNS is required.
3. Evaluate the first matching domain rule before scheduled/category fallback.
   Preserve existing matching: simple also covers www; wildcard covers the root
   and every subdomain. Invalid rules fail validation. Monitor permits and logs.
4. Require a new agent capability before delivery or successful ACK. Existing
   agent builds must not silently ignore ordered policies. Keep legacy policies
   unchanged until edited/published. Migrate their allow list before block list.
5. Replace permanent-domain textareas with an accessible table, add/edit/remove,
   order controls, CSV preview and explicit import into the draft. Export the
   current draft. Import appends; invalid or conflicting exact duplicates prevent
   the whole import, without discarding existing rows. Overlapping distinct
   patterns remain valid because order resolves them.
6. CSV schema: `domain,type,action`; export simple/wildcard and allow/block/monitor,
   accept normal/log aliases on input. Support quoted fields, UTF-8 BOM, CRLF,
   comma/semicolon delimiters, bounded file size and 10,000-rule policy limit.
   Display line errors; reject URLs, IPs, formulas and unsupported pattern syntax.
7. Regenerate shared Python/Rust vectors, run all permitted host tests, panel
   coverage/lint/typecheck/build and native fmt/clippy/tests. Preserve the four
   existing host harness deselections and keep service/MSI tests disabled.
8. Commit local logical units; no push, PR, CI changes or rollout. Keep Windows
   acceptance on its original branch with immutable 918aba2 package bytes.

## Risks and verification

- Reordering can change access. Tests compare both orders, overlapping rules,
  simple/wildcard, www, unrelated hosts, schedules and category precedence.
- Migration must preserve legacy allow priority and all non-domain profile fields.
- Old agents cannot fetch or acknowledge the new capability; test server guards.
- CSV must round-trip order/actions and report malformed rows without partial
  imports. Test BOM, quoting, Unicode, duplicates, file errors and limits.
- Read-only roles cannot mutate/import/publish. Test keyboard/focus, dark-theme
  token usage and failure/conflict UI. Automated tests do not replace guest DNS
  enforcement or manual browser acceptance for the eventual new agent build.

## Concurrent acceptance

USB reacceptance uses the frozen 918aba2 ISO and shortcut 15 in a clean UID 2
snapshot, after preserving the WDAC diagnostic guest state in a separate snapshot.
The new web feature is not included in that package or its acceptance claims.
