-- =====================================================================
-- MalSense - add the REPORTS table (users report APKs MalSense could not analyse,
-- or where they think the result is wrong). Run once, logged in as root:
--     source C:/Users/User/Desktop/MalSense/database/migrate_add_reports.sql
-- =====================================================================
USE malsense;

CREATE TABLE IF NOT EXISTS reports (
  report_id      INT AUTO_INCREMENT PRIMARY KEY,
  user_id        INT           NULL,                     -- NULL = reported by a guest
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

DESCRIBE reports;
