-- =====================================================================
-- MalSense database for TiDB Cloud (online) - the same tables as schema.sql, without CREATE USER
-- (TiDB Cloud gives you the database user in its "Connect" dialog).
-- Run it in TiDB Cloud's SQL Editor (select everything, then Run), or from your laptop:
--   mysql --comments -h <host> -P 4000 -u <user> -p --ssl-mode=VERIFY_IDENTITY < database/tidb_setup.sql
-- =====================================================================
CREATE DATABASE IF NOT EXISTS malsense CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE malsense;

-- 3. USERS
CREATE TABLE IF NOT EXISTS users (
  user_id        INT AUTO_INCREMENT PRIMARY KEY,
  username       VARCHAR(100)  NOT NULL,                 -- full name shown in the app
  email          VARCHAR(255)  NOT NULL UNIQUE,          -- used to log in; must be unique
  password_hash  VARCHAR(255)  NOT NULL,                 -- bcrypt hash, never the real password
  role           ENUM('user','admin') NOT NULL DEFAULT 'user',
  is_active      TINYINT(1)    NOT NULL DEFAULT 1,       -- admin can deactivate an account
  is_verified    BOOLEAN       NOT NULL DEFAULT FALSE,   -- clicked the email verification link
  created_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login     DATETIME      NULL
) ENGINE=InnoDB;

-- 4. SCANS - user_id is NULL for guest scans
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
  details        JSON          NULL,                     -- full analysis (result page + downloadable report)
  CONSTRAINT fk_scans_user FOREIGN KEY (user_id) REFERENCES users(user_id)
    ON DELETE SET NULL,                                   -- deleting a user keeps the scan logs
  UNIQUE KEY uq_user_scan_no (user_id, user_scan_no)
) ENGINE=InnoDB;

-- 5. REPORTS - APKs users send to the admin (could not be analysed / result looks wrong)
CREATE TABLE IF NOT EXISTS reports (
  report_id      INT AUTO_INCREMENT PRIMARY KEY,
  user_id        INT           NULL,
  filename       VARCHAR(255)  NOT NULL,                 -- name the user uploaded
  stored_name    VARCHAR(64)   NOT NULL,                 -- random file name in reported_apks/
  file_hash      VARCHAR(64)   NOT NULL,                 -- SHA-256
  file_size      INT           NOT NULL,                 -- bytes
  reason         ENUM('scan_failed','wrong_result','new_malware','other') NOT NULL,
  message        TEXT          NULL,
  contact_email  VARCHAR(255)  NULL,
  status         ENUM('new','added_malware','added_benign','dismissed') NOT NULL DEFAULT 'new',
  created_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  reviewed_at    DATETIME      NULL,
  CONSTRAINT fk_reports_user FOREIGN KEY (user_id) REFERENCES users(user_id)
    ON DELETE SET NULL
) ENGINE=InnoDB;

-- 6. QUIZ_LOG - one row per quiz made (daily quiz limit)
CREATE TABLE IF NOT EXISTS quiz_log (
  log_id      INT AUTO_INCREMENT PRIMARY KEY,
  user_id     INT          NOT NULL,
  created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_quiz_log_user_day (user_id, created_at),
  CONSTRAINT fk_quiz_log_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 7. QUIZ_CACHE - saved quizzes + per-app question history (used by the online version;
--    the laptop version keeps them as files in quiz_cache/, so this table simply stays empty there)
CREATE TABLE IF NOT EXISTS quiz_cache (
  cache_key   VARCHAR(80)  NOT NULL PRIMARY KEY,          -- "quiz_<id>" or "history_<sha256>"
  data        JSON         NOT NULL,
  updated_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 8. Show the result
SHOW TABLES;
