from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app import db


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    session_version = db.Column(db.Integer, default=1, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    executions = db.relationship("Execution", back_populates="user", lazy=True)

    def set_password(self, raw_password: str) -> None:
        self.password_hash = generate_password_hash(raw_password, method="pbkdf2:sha256")

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password_hash, raw_password)

    def revoke_sessions(self) -> None:
        self.session_version += 1


class LoginAttempt(db.Model):
    __tablename__ = "login_attempts"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(64), unique=True, nullable=False)
    fail_count = db.Column(db.Integer, default=0, nullable=False)
    last_attempt = db.Column(db.DateTime, default=datetime.now)
    banned_until = db.Column(db.DateTime, nullable=True)

    def is_banned(self) -> bool:
        return bool(self.banned_until and self.banned_until > datetime.now())


class LoginAttemptLog(db.Model):
    __tablename__ = "login_attempt_logs"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(64), nullable=False)
    username_tried = db.Column(db.String(80), nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    attempted_at = db.Column(db.DateTime, default=datetime.now)


class AccountAttempt(db.Model):
    """v1.2: per-account progressive lockout, complementing the existing
    per-IP one. A distributed attacker rotating IPs was previously
    unthrottled as long as they spread failed attempts across enough
    addresses; this throttles by *username* instead, growing the delay with
    repeated failures rather than an indefinite hard lock, so it can't itself
    be used to permanently deny a legitimate user (see SECURITY.md)."""

    __tablename__ = "account_attempts"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    fail_count = db.Column(db.Integer, default=0, nullable=False)
    last_attempt = db.Column(db.DateTime, default=datetime.now)
    locked_until = db.Column(db.DateTime, nullable=True)

    def is_locked(self) -> bool:
        return bool(self.locked_until and self.locked_until > datetime.now())


class Execution(db.Model):
    __tablename__ = "executions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    server_id = db.Column(db.String(16), nullable=False)
    server_host = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(64), nullable=False)
    script_name = db.Column(db.String(128), nullable=False)
    status = db.Column(db.String(16), default="running", nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.now)
    finished_at = db.Column(db.DateTime, nullable=True)
    log_filename = db.Column(db.String(255), nullable=False)
    triggered_by = db.Column(db.String(80), nullable=False)
    # v1.2: SHA-256 of the exact script bytes that were actually uploaded and
    # run for this execution, captured once at /run time (see main.py) — an
    # audit trail independent of whatever the source script file looks like
    # afterwards.
    script_sha256 = db.Column(db.String(64), nullable=True)
    user = db.relationship("User", back_populates="executions")
