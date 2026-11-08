"""
MalSense database models - match the MySQL tables in database/schema.sql (thesis Figure 4.6).
The tables are created by schema.sql; these classes just let Flask read and write them.
"""
from datetime import datetime
import bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum("user", "admin"), nullable=False, default="user")
    active = db.Column("is_active", db.Boolean, nullable=False, default=True)   # admin can deactivate (UC07)
    verified = db.Column("is_verified", db.Boolean, nullable=False, default=False)  # clicked the email link
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    last_login = db.Column(db.DateTime)

    def get_id(self):                      # Flask-Login needs this
        return str(self.user_id)

    def set_password(self, password):
        """Store only a bcrypt hash (with a random salt) - never the real password."""
        self.password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def check_password(self, password):
        return bcrypt.checkpw(password.encode(), self.password_hash.encode())

    @property
    def is_active(self):                    # Flask-Login refuses to log in inactive users
        return bool(self.active)

    @property
    def is_admin(self):
        return self.role == "admin"


class Scan(db.Model):
    __tablename__ = "scans"
    scan_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="SET NULL"))
    user_scan_no = db.Column(db.Integer)  # 1, 2, 3... counted separately for EACH user (shown in the URL)
    filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.String(50), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    package_name = db.Column(db.String(255))
    sdk_version = db.Column(db.String(50))
    ml_result = db.Column(db.Enum("Malware", "Benign"), nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    vt_result = db.Column(db.String(50))
    scan_duration = db.Column(db.Float)
    scanned_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    details = db.Column(db.JSON)          # full analysis (for the downloadable report) - added by migration

class Report(db.Model):
    """An APK a user reported to the admin (MalSense could not analyse it, or the result looks wrong).
    The APK itself is kept in reported_apks/ so the admin can study it and add it to the training data."""
    __tablename__ = "reports"
    report_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="SET NULL"))   # NULL = guest
    filename = db.Column(db.String(255), nullable=False)          # name the user uploaded
    stored_name = db.Column(db.String(64), nullable=False)        # random name on disk (reported_apks/)
    file_hash = db.Column(db.String(64), nullable=False)          # SHA-256
    file_size = db.Column(db.Integer, nullable=False)             # bytes
    reason = db.Column(db.Enum("scan_failed", "wrong_result", "new_malware", "other"), nullable=False)
    message = db.Column(db.Text)
    contact_email = db.Column(db.String(255))
    status = db.Column(db.Enum("new", "added_malware", "added_benign", "dismissed"), nullable=False, default="new")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    reviewed_at = db.Column(db.DateTime)

    REASONS = {"scan_failed": "MalSense could not analyse it",
               "wrong_result": "I think the result is wrong",
               "new_malware": "It is new malware MalSense missed",
               "other": "Other"}
    STATUSES = {"new": "New", "added_malware": "Added as malware", "added_benign": "Added as benign",
                "dismissed": "Dismissed"}


class TesterRequest(db.Model):
    """Someone asking to join MalSense's user testing (splash screen > Join as a tester).
    The admin approves the request in Admin > Testers, which emails them the site access code."""
    __tablename__ = "tester_requests"
    request_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    reason = db.Column(db.Text, nullable=False)                     # why they want to join
    consent_at = db.Column(db.DateTime, nullable=False)             # when they ticked the consent box
    status = db.Column(db.Enum("pending", "approved", "rejected"), nullable=False, default="pending")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    decided_at = db.Column(db.DateTime)                             # approved / rejected
    code_sent_at = db.Column(db.DateTime)                           # last time the code was emailed

    STATUSES = {"pending": "Waiting", "approved": "Approved", "rejected": "Rejected"}


class QuizLog(db.Model):
    """One row each time a user makes an awareness quiz - used for the daily quiz limit."""
    __tablename__ = "quiz_log"
    log_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

class QuizCache(db.Model):
    """Saved quizzes and per-app question history (was the quiz_cache/ folder).
    Kept in the database because the online server forgets its files when it restarts.
    key = "quiz_<32 hex>" or "history_<sha256>", data = the JSON that used to be in the file."""
    __tablename__ = "quiz_cache"
    cache_key = db.Column(db.String(80), primary_key=True)
    data = db.Column(db.JSON, nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.now, onupdate=datetime.now)
