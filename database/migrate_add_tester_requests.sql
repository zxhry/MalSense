-- =====================================================================
-- MalSense - add the TESTER_REQUESTS table (splash screen > "Join as a tester").
-- The admin approves requests in Admin > Testers, which emails the site access code.
-- Run once:   source C:/Users/User/Desktop/MalSense/database/migrate_add_tester_requests.sql
-- =====================================================================
USE malsense;

CREATE TABLE IF NOT EXISTS tester_requests (
  request_id     INT AUTO_INCREMENT PRIMARY KEY,
  name           VARCHAR(100)  NOT NULL,
  email          VARCHAR(255)  NOT NULL UNIQUE,
  reason         TEXT          NOT NULL,                 -- why they want to join
  consent_at     DATETIME      NOT NULL,                 -- when they agreed to the consent statement
  status         ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
  created_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  decided_at     DATETIME      NULL,
  code_sent_at   DATETIME      NULL
) ENGINE=InnoDB;

DESCRIBE tester_requests;
