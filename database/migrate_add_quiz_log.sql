-- Daily quiz limit: one row each time a user makes an awareness quiz.
USE malsense;
CREATE TABLE IF NOT EXISTS quiz_log (
  log_id      INT AUTO_INCREMENT PRIMARY KEY,
  user_id     INT          NOT NULL,
  created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_quiz_log_user_day (user_id, created_at),
  CONSTRAINT fk_quiz_log_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
