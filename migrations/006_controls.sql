-- Bounded endpoint inventory and idempotent application/USB control events.
CREATE TABLE IF NOT EXISTS endpoint_inventory (
    devid TEXT PRIMARY KEY,
    collected_at TIMESTAMPTZ NOT NULL,
    snapshot JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS control_events (
    id TEXT PRIMARY KEY,
    devid TEXT NOT NULL,
    at TIMESTAMPTZ NOT NULL,
    kind TEXT NOT NULL,
    payload JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_control_events_at ON control_events(at);
CREATE INDEX IF NOT EXISTS idx_endpoint_inventory_collected ON endpoint_inventory(collected_at);
