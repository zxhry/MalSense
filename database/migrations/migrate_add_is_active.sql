-- MalSense migration: let the admin activate / deactivate user accounts (UC07).
-- Run inside the MySQL client (logged in as root):
--     source C:/Users/User/Desktop/MalSense/database/migrate_add_is_active.sql
USE malsense;
ALTER TABLE users ADD COLUMN is_active TINYINT(1) NOT NULL DEFAULT 1 AFTER role;
DESCRIBE users;