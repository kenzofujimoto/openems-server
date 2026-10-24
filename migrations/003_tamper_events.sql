-- Tamper events (F5): protections an agent found altered and restored, purged after retention.
CREATE TABLE IF NOT EXISTS tamper_events (
    id     BIGSERIAL PRIMARY KEY,
    devid  TEXT NOT NULL,
    at     TIMESTAMPTZ NOT NULL,
    kind   TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_tamper_events_at ON tamper_events (at);
