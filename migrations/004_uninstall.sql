-- Uninstall codes (F5 part 5b). Keyed by client_id: a new client_id means a new secret, so it starts over
-- with counter 0 and a pending delivery. Kept out of endpoints, whose upsert rewrites the whole row.
CREATE TABLE IF NOT EXISTS uninstall_state (
    client_id    TEXT PRIMARY KEY,
    counter      BIGINT NOT NULL DEFAULT 0 CHECK (counter >= 0),
    secret_acked BOOLEAN NOT NULL DEFAULT FALSE
);
-- Removal released without a code for a policy group, or for the whole fleet with scope '*'.
CREATE TABLE IF NOT EXISTS uninstall_releases (
    scope       TEXT PRIMARY KEY,
    released_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_by TEXT NOT NULL
);
