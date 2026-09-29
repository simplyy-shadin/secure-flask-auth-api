from datetime import UTC, datetime

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from .extensions import db


password_hasher = PasswordHasher()


def utcnow():
    # SQLAlchemy columns are intentionally stored as naive UTC timestamps.
    return datetime.now(UTC).replace(tzinfo=None)


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
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    mfa_secret_encrypted = db.Column(db.Text, nullable=True)
    mfa_last_used_step = db.Column(db.BigInteger, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    sessions = db.relationship(
        "AuthSession", back_populates="user", cascade="all, delete-orphan"
    )
    recovery_codes = db.relationship(
        "MfaRecoveryCode", back_populates="user", cascade="all, delete-orphan"
    )
    mfa_challenges = db.relationship(
        "MfaChallenge", back_populates="user", cascade="all, delete-orphan"
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
    mfa_authenticated = db.Column(db.Boolean, nullable=False, default=False)

    user = db.relationship("User", back_populates="sessions")

    def is_valid(self):
        return self.revoked_at is None and self.expires_at > utcnow()

    def revoke(self, reason):
        if self.revoked_at is None:
            self.revoked_at = utcnow()
            self.revoke_reason = reason


class MfaRecoveryCode(db.Model):
    __tablename__ = "mfa_recovery_codes"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    code_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    used_at = db.Column(db.DateTime, nullable=True, index=True)

    user = db.relationship("User", back_populates="recovery_codes")


class MfaChallenge(db.Model):
    __tablename__ = "mfa_challenges"

    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    consumed_at = db.Column(db.DateTime, nullable=True, index=True)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    source_ip = db.Column(db.String(45), nullable=True)

    user = db.relationship("User", back_populates="mfa_challenges")

    def is_valid(self, max_attempts):
        return (
            self.consumed_at is None
            and self.expires_at > utcnow()
            and self.attempts < max_attempts
        )


class AuditEvent(db.Model):
    __tablename__ = "audit_events"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    user_id = db.Column(db.Integer, nullable=True, index=True)
    request_id = db.Column(db.String(36), nullable=False, index=True)
    source_ip = db.Column(db.String(45), nullable=True)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
