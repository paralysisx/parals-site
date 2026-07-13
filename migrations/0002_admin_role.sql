-- Adds an admin role so an account can approve/decline sign-ups from the /admin
-- panel. Grants admin to the hub owner. Run once against the live database.

ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user';

UPDATE users SET role = 'admin' WHERE username = 'Paralysis';
