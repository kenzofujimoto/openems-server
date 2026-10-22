-- Non-destructive baseline for existing installations and new deployments.
CREATE TABLE IF NOT EXISTS endpoints (
    devid TEXT PRIMARY KEY,
    client_id TEXT UNIQUE NOT NULL,
    hostname TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL DEFAULT '',
    fctver TEXT NOT NULL DEFAULT '',
    vdom TEXT NOT NULL DEFAULT 'Default',
    status TEXT NOT NULL DEFAULT 'registered',
    reg_ip TEXT NOT NULL DEFAULT '',
    host_tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_endpoints_client_id ON endpoints (client_id);
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS credential_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS config_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS applied_vdom TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS applied_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS last_error TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS last_applied TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS profiles (
    vdom TEXT PRIMARY KEY,
    version INTEGER NOT NULL DEFAULT 0,
    body JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS assignment_rules (
    id TEXT PRIMARY KEY,
    target_vdom TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 100,
    enabled BOOLEAN NOT NULL DEFAULT true,
    conditions JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE TABLE IF NOT EXISTS admins (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin'
);
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE IF NOT EXISTS enrollment_invitations (
    token_hash TEXT PRIMARY KEY,
    vdom TEXT NOT NULL,
    max_uses INTEGER NOT NULL CHECK (max_uses > 0),
    used INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_sessions (
    sid TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    credential_fingerprint TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS admin_sessions_expiry ON admin_sessions (expires_at);
CREATE TABLE IF NOT EXISTS admin_login_limits (
    bucket_key TEXT PRIMARY KEY,
    expires_at DOUBLE PRECISION NOT NULL,
    attempts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS admin_login_limits_expiry ON admin_login_limits (expires_at);
CREATE TABLE IF NOT EXISTS saml_idps (
    prefix TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL,
    sso_url TEXT NOT NULL,
    certificate TEXT NOT NULL
);
