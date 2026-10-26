-- Preserve revocation across bootstrap-token provisioning on server restart.
ALTER TABLE enrollment_invitations ADD COLUMN IF NOT EXISTS revoked BOOLEAN NOT NULL DEFAULT false;
