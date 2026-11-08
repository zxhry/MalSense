-- =====================================================================
-- MalSense database - matches thesis Figure 4.6 (Entity-Relationship Diagram)
-- Run inside the MySQL client (logged in as root):
--     source C:/Users/User/Desktop/MalSense/database/schema.sql
-- BEFORE running: replace  CHANGE_ME_app_password  below with your own password.
-- =====================================================================

-- 1. The database
CREATE DATABASE IF NOT EXISTS malsense
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 2. A separate account for the Flask app (safer than letting the app use root:
--    it can only touch the malsense database, nothing else on the server)
CREATE USER IF NOT EXISTS 'malsense_app'@'localhost' IDENTIFIED BY 'CHANGE_ME_app_password';
GRANT SELECT, INSERT, UPDATE, DELETE ON malsense.* TO 'malsense_app'@'localhost';
FLUSH PRIVILEGES;

USE malsense;

-- 3. USERS table (Figure 4.6)
CREATE TABLE IF NOT EXISTS users (
  user_id        INT AUTO_INCREMENT PRIMARY KEY,
  username       VARCHAR(100)  NOT NULL,                 -- full name shown in the app
  email          VARCHAR(255)  NOT NULL UNIQUE,          -- used to log in; must be unique
  password_hash  VARCHAR(255)  NOT NULL,                 -- bcrypt hash, never the real password
  role           ENUM('user','admin') NOT NULL DEFAULT 'user',
  created_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login     DATETIME      NULL
) ENGINE=InnoDB;

-- 4. SCANS table (Figure 4.6). user_id is NULL for guest scans (no account needed to scan)
CREATE TABLE IF NOT EXISTS scans (
  scan_id        INT AUTO_INCREMENT PRIMARY KEY,
  user_id        INT           NULL,
  user_scan_no   INT           NULL,                     -- 1, 2, 3... per user (shown in the URL)
  filename       VARCHAR(255)  NOT NULL,
  file_size      VARCHAR(50)   NOT NULL,                 -- e.g. "0.8 MB"
  file_hash      VARCHAR(64)   NOT NULL,                 -- SHA-256
  package_name   VARCHAR(255)  NULL,
  sdk_version    VARCHAR(50)   NULL,
  ml_result      ENUM('Malware','Benign') NOT NULL,
  confidence     FLOAT         NOT NULL,                 -- 0-100 (%)
  vt_result      VARCHAR(50)   NULL,                     -- e.g. "0/67" or "not found"
  scan_duration  FLOAT         NULL,                     -- seconds
  scanned_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_scans_user FOREIGN KEY (user_id) REFERENCES users(user_id)
    ON DELETE SET NULL,                                   -- deleting a user keeps the scan logs
  UNIQUE KEY uq_user_scan_no (user_id, user_scan_no)
) ENGINE=InnoDB;

-- 5. Show the result
SHOW TABLES;
DESCRIBE users;
DESCRIBE scans;