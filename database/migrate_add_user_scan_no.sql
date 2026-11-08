-- MalSense migration: number each user's scans separately (1, 2, 3 ...) instead of one global counter.
-- scan_id stays as the hidden, unique primary key; user_scan_no is what appears in the URL /result/<n>.
-- Run inside the MySQL client (logged in as root):
--     source C:/Users/User/Desktop/MalSense/database/migrate_add_user_scan_no.sql
USE malsense;

ALTER TABLE scans ADD COLUMN user_scan_no INT NULL AFTER user_id;

-- Give the scans that already exist their per-user number, oldest first
UPDATE scans s
JOIN (SELECT scan_id,
             ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY scanned_at, scan_id) AS n
      FROM scans WHERE user_id IS NOT NULL) x ON s.scan_id = x.scan_id
SET s.user_scan_no = x.n;

-- One user can never have two scans with the same number (guest scans stay NULL)
ALTER TABLE scans ADD UNIQUE KEY uq_user_scan_no (user_id, user_scan_no);

SELECT user_id, user_scan_no, scan_id, filename FROM scans ORDER BY user_id, user_scan_no;