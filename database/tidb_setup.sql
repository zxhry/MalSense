-- =====================================================================
-- MalSense database for TiDB Cloud (online). This is schema.sql + every migrate_*.sql already applied,
-- plus the new quiz_cache table (quizzes used to be files in quiz_cache/).
-- Run it in TiDB Cloud's SQL Editor, or from your laptop:
--   mysql --comments -h <host> -P 4000 -u <user> -p --ssl-mode=VERIFY_IDENTITY < database/tidb_setup.sql
-- (No CREATE USER here: TiDB Cloud gives you the database user in its "Connect" dialog.)
-- =====================================================================
CREATE DATABASE IF NOT EXISTS malsense CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE malsense;

CREATE TABLE IF NOT EXISTS users (
  user_id        INT AUTO_INCREMENT PRIMARY KEY,
  username       VARCHAR(100)  NOT NULL,
  email          VARCHAR(255)  NOT NULL UNIQUE,
  password_hash  VARCHAR(255)  NOT NULL,
  role           ENUM('user','admin') NOT NULL DEFAULT 'user',
  is_active      TINYINT(1)    NOT NULL DEFAULT 1,
  is_verified    BOOLEAN       NOT NULL DEFAULT FALSE,
  created_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login     DATETIME      NULL
);

CREATE TABLE IF NOT EXISTS scans (
  scan_id        INT AUTO_INCREMENT PRIMARY KEY,
  user_id        INT           NULL,
  user_scan_no   INT           NULL,
  filename       VARCHAR(255)  NOT NULL,
  file_size      VARCHAR(50)   NOT NULL,
  file_hash      VARCHAR(64)   NOT NULL,
  package_name   VARCHAR(255)  NULL,
  sdk_version    VARCHAR(50)   NULL,
  ml_result      ENUM('Malware','Benign') NOT NULL,
  confidence     FLOAT         NOT NULL,
  vt_result      VARCHAR(50)   NULL,
  scan_duration  FLOAT         NULL,
  scanned_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  details        JSON          NULL,
  CONSTRAINT fk_scans_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL,
  UNIQUE KEY uq_user_scan_no (user_id, user_scan_no)
);

CREATE TABLE IF NOT EXISTS reports (
  report_id      INT AUTO_INCREMENT PRIMARY KEY,
  user_id        INT           NULL,
  filename       VARCHAR(255)  NOT NULL,
  stored_name    VARCHAR(64)   NOT NULL,
  file_hash      VARCHAR(64)   NOT NULL,
  file_size      INT           NOT NULL,
  reason         ENUM('scan_failed','wrong_result','new_malware','other') NOT NULL,
  message        TEXT          NULL,
  contact_email  VARCHAR(255)  NULL,
  status         ENUM('new','added_malware','added_benign','dismissed') NOT NULL DEFAULT 'new',
  created_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  reviewed_at    DATETIME      NULL,
  CONSTRAINT fk_reports_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
);

-- NEW: saved quizzes + per-app question history (key "quiz_<id>" or "history_<sha256>")
CREATE TABLE IF NOT EXISTS quiz_cache (
  cache_key      VARCHAR(80)   NOT NULL PRIMARY KEY,
  data           JSON          NOT NULL,
  updated_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Daily quiz limit: one row each time a user makes an awareness quiz
CREATE TABLE IF NOT EXISTS quiz_log (
  log_id      INT AUTO_INCREMENT PRIMARY KEY,
  user_id     INT          NOT NULL,
  created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_quiz_log_user_day (user_id, created_at),
  CONSTRAINT fk_quiz_log_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

SHOW TABLES;

-- ---------------------------------------------------------------------
-- Tester requests (splash screen > "Join as a tester"; approved in Admin > Testers)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tester_requests (
  request_id     INT AUTO_INCREMENT PRIMARY KEY,
  name           VARCHAR(100)  NOT NULL,
  email          VARCHAR(255)  NOT NULL UNIQUE,
  reason         TEXT          NOT NULL,
  consent_at     DATETIME      NOT NULL,
  status         ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
  created_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  decided_at     DATETIME      NULL,
  code_sent_at   DATETIME      NULL
);
