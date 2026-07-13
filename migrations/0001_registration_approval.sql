-- Adds admin-approval gating to registration.
-- Run once against the existing D1 database. Existing accounts are grandfathered
-- in as 'approved' so no one gets locked out; only new sign-ups start 'pending'.

ALTER TABLE users ADD COLUMN email TEXT;
ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'approved';
ALTER TABLE users ADD COLUMN approval_token TEXT;

CREATE INDEX IF NOT EXISTS idx_users_approval_token ON users(approval_token);
