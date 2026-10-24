-- Block log (F2 slice 4b): hourly aggregates of blocked DNS answers, purged after retention.
CREATE TABLE IF NOT EXISTS block_events (
    devid    TEXT NOT NULL,
    hour     TIMESTAMPTZ NOT NULL,
    domain   TEXT NOT NULL,
    reason   TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    count    BIGINT NOT NULL CHECK (count > 0),
    PRIMARY KEY (devid, hour, domain, reason, category)
);
CREATE INDEX IF NOT EXISTS idx_block_events_hour ON block_events (hour);
