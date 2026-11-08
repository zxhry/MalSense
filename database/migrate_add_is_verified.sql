-- =====================================================================
-- MalSense - email verification. Adds users.is_verified (run once, logged in as root):
--     source C:/Users/User/Desktop/MalSense/database/migrate_add_is_verified.sql
-- Accounts that already exist are marked as verified, so nobody is locked out.
-- New accounts start as NOT verified until the user clicks the link in the email.
-- =====================================================================
USE malsense;

ALTER TABLE users ADD COLUMN is_verified BOOLEAN NOT NULL DEFAULT FALSE AFTER is_active;
UPDATE users SET is_verified = TRUE;

DESCRIBE users;
