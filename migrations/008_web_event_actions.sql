ALTER TABLE block_events ADD COLUMN IF NOT EXISTS action TEXT NOT NULL DEFAULT 'blocked'
    CHECK (action IN ('blocked', 'monitored'));
ALTER TABLE block_events ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'dns'
    CHECK (source IN ('dns'));
ALTER TABLE block_events DROP CONSTRAINT IF EXISTS block_events_pkey;
ALTER TABLE block_events ADD PRIMARY KEY (devid, hour, domain, reason, category, action, source);

CREATE TABLE IF NOT EXISTS web_event_batches (
    devid TEXT NOT NULL,
    batch_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (devid, batch_id)
);
CREATE INDEX IF NOT EXISTS idx_web_event_batches_received_at ON web_event_batches (received_at);
