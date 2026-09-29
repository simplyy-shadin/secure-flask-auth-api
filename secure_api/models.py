from datetime import datetime

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from .extensions import db


password_hasher = PasswordHasher()


def utcnow():
    return datetime.utcnow()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False, index=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    sessions = db.relationship(
        "AuthSession", back_populates="user", cascade="all, delete-orphan"
    )

    def set_password(self, password):
        self.password_hash = password_hasher.hash(password)

    def check_password(self, password):
        try:
            valid = password_hasher.verify(self.password_hash, password)
            if valid and password_hasher.check_needs_rehash(self.password_hash):
                self.password_hash = password_hasher.hash(password)
            return valid
        except (VerifyMismatchError, InvalidHashError):
            return False

    def is_locked(self):
        return self.locked_until is not None and self.locked_until > utcnow()


class AuthSession(db.Model):
    __tablename__ = "auth_sessions"

    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    refresh_jti = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_rotated_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    revoked_at = db.Column(db.DateTime, nullable=True, index=True)
    revoke_reason = db.Column(db.String(64), nullable=True)
    source_ip = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)

    user = db.relationship("User", back_populates="sessions")

    def is_valid(self):
        return self.revoked_at is None and self.expires_at > utcnow()

    def revoke(self, reason):
        if self.revoked_at is None:
            self.revoked_at = utcnow()
            self.revoke_reason = reason


class AuditEvent(db.Model):
    __tablename__ = "audit_events"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    user_id = db.Column(db.Integer, nullable=True, index=True)
    request_id = db.Column(db.String(36), nullable=False, index=True)
    source_ip = db.Column(db.String(45), nullable=True)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
