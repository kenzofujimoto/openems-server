# Web action contract

This is an OpenEMS extension, separate from the observed interoperability protocol in `SPEC-INTEROP.md`. The approved behavior and acceptance matrix are in [the plan](web-filter-actions-plan.md) and [the acceptance guide](web-filter-actions-acceptance.md).

## Policy

```json
{
  "web_filter": {
    "category_actions": {"adult": "block", "streaming": "monitor", "bank": "allow"},
    "monitor_all": false,
    "allowed": ["*.netflix.com"]
  }
}
```

`category_actions` accepts known category IDs and `allow`, `block`, `monitor` or `warn`; domain rules accept the same actions. Scheduled windows also accept this map. Legacy `blocked_categories` remains supported; an ID shared with the new map must have action `block`, otherwise validation rejects the conflict. Explicit domain exceptions take priority. Among matching categories, block wins over warn, warn over monitor, then allow. Legacy category ties retain list order; new map ties use lexical IDs so Python and Rust agree.

An explicit allow suppresses navigation events for that web decision. Administrative audit and independent anti-bypass controls remain separate. Without a matching category action, `monitor_all` determines observation; it defaults to false. This fallback does not classify a domain as an authoritative “unrated” category.

New action policies require agent capabilities `web-filter:actions`, plus `web-filter:monitor` for monitoring and `web-filter:categories` for category membership. DNS capability is required where applicable. Unsupported agents receive HTTP 409 when fetching the assigned new policy or acknowledging it successfully. They must advertise capabilities before fetching a new action assignment, including after reenrollment.

All referenced category sets, including allow exclusions, must be present and nonempty before a new action policy is activated or acknowledged. Missing data must not silently turn an allow exclusion into monitored traffic. A failed update preserves the previous valid active policy and category cache.

### Warning (`warn`)

The native agent answers a warned name locally (DNS TTL 2 s) and serves a warning page over HTTP and HTTPS with a "continue" form. The form posts to `/__openems/proceed?token=<64 hex>` on the same host; the token is random, single use, bound to that host and valid for 10 minutes. A valid continue lasts 60 minutes for the whole category, or for the domain when a domain rule warns; afterwards the name is treated as monitored (logged). Blocked names can never be continued past. The interrupted attempt is recorded as a blocked DNS event with its rule or category reason, so no event schema changes.

Policies using `warn` require `web-filter:warn`. The native agent advertises it only with the DNS filter and both local block pages (HTTP and HTTPS) enabled, because an HTTPS site without the local certificate could not show the form. The Python reference agent shares the decision logic and vectors but does not advertise the capability. Continues are kept in memory per machine and are lost when the agent restarts.

## DNS event upload

`POST /fct/api/public/v1/events/` retains device authentication and legacy rows. The new optional envelope `batch_id` is 64 lowercase hexadecimal characters. It identifies an immutable batch; retries reuse its ID and payload. A repeated identical batch is not counted twice; reusing an ID for another payload receives HTTP 409. Legacy uploads without an ID retain legacy behavior.

The in-memory store caps batch receipts at 100,000 and responds HTTP 429 when full; retention purges old receipts. PostgreSQL persists receipts transactionally and remains the deployment storage option for sustained fleet telemetry.

Rows add `action` (`blocked` or `monitored`) and `source` (`dns`); omitted fields default to `blocked` and `dns`. Monitor-all events use reason `policy`; category observations use `category`. Blocked events cannot use `policy`, and monitored events cannot use `doh`. The `browser` source is not supported by this contract or migration 008.

The native queue aggregates by machine, hour, domain, reason, category, action and source. Repeated matching observations are deduplicated per minute. Queue, pending upload and deduplication identities are bounded in memory; discarded observations are reported separately. Under saturation, dropped counts are not unique-domain or person counts. Queue contents are not a durable browser history.

PostgreSQL migration `008_web_event_actions.sql` adds action/source to event identity and stores transactional batch receipts. Retention remains configurable from 1 to 365 days, default 30. Existing role checks and read auditing remain applicable. No Windows username, full URL, query or fragment is added to DNS events.

## Panel

Event kind `web_block` remains a block; `web_monitor` denotes observation. `/api/v1/events` accepts an optional `action=blocked|monitored` filter. Overview `blocks` and blocked-domain rankings exclude monitoring and dropped observations; `monitoring_by_day` and `dropped_by_day` expose separate totals.

Category publication health is exposed to the panel with missing, empty, stale, current or invalid status. It describes publication availability and age, not guaranteed classification coverage. The agent-facing manifest keeps its existing shape.
