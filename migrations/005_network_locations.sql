-- F6: policy choice based on network signals remains local to the agent.
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS location TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS network_locations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    definition JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS location_policies (
    vdom TEXT NOT NULL,
    location_id TEXT NOT NULL REFERENCES network_locations(id) ON DELETE CASCADE,
    inside_vdom TEXT NOT NULL,
    PRIMARY KEY (vdom, location_id)
);
