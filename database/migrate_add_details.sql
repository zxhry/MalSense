-- MalSense migration: store the full analysis of each scan so a report can be downloaded later.
-- Run inside the MySQL client (logged in as root):
--     source C:/Users/User/Desktop/MalSense/database/migrate_add_details.sql
USE malsense;
ALTER TABLE scans ADD COLUMN details JSON NULL AFTER scanned_at;
DESCRIBE scans;