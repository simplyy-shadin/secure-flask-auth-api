import hmac
import secrets
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pyotp
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from flask import current_app
from flask_jwt_extended import create_access_token

from .extensions import db
from .models import MfaChallenge, MfaRecoveryCode, password_hasher, utcnow
from .security import source_ip


def _fernet():
    return Fernet(current_app.config["MFA_ENCRYPTION_KEY"].encode())


def encrypt_secret(secret):
    return _fernet().encrypt(secret.encode()).decode()


def decrypt_secret(encrypted_secret):
    if not encrypted_secret:
        return None
    try:
        return _fernet().decrypt(encrypted_secret.encode()).decode()
    except InvalidToken:
        return None


def generate_totp_secret():
    return pyotp.random_base32()


def provisioning_uri(user, secret):
    return pyotp.TOTP(secret).provisioning_uri(
        name=user.email,
        issuer_name=current_app.config["TOTP_ISSUER_NAME"],
    )


def create_login_challenge(user):
    challenge = MfaChallenge(
        id=str(uuid4()),
        user_id=user.id,
        expires_at=utcnow()
        + timedelta(minutes=current_app.config["MFA_CHALLENGE_MINUTES"]),
        source_ip=source_ip(),
    )
    db.session.add(challenge)
    mfa_token = create_access_token(
        identity=str(user.id),
        additional_claims={
            "stage": "mfa_login",
            "cid": challenge.id,
        },
        expires_delta=timedelta(
            minutes=current_app.config["MFA_CHALLENGE_MINUTES"]
        ),
        fresh=False,
    )
    return challenge, mfa_token


def _matched_totp_step(secret, code):
    if not isinstance(code, str) or not code.isdigit() or len(code) != 6:
        return None

    totp = pyotp.TOTP(secret)
    now = datetime.now(UTC)
    current_step = totp.timecode(now)
    valid_window = current_app.config["TOTP_VALID_WINDOW"]

    for offset in range(-valid_window, valid_window + 1):
        step = current_step + offset
        expected = totp.generate_otp(step)
        if hmac.compare_digest(expected, code):
            return step
    return None


def verify_totp(user, code, consume=True):
    secret = decrypt_secret(user.mfa_secret_encrypted)
    if not secret:
        return False

    step = _matched_totp_step(secret, code)
    if step is None:
        return False

    if user.mfa_last_used_step is not None and step <= user.mfa_last_used_step:
        return False

    if consume:
        user.mfa_last_used_step = step
    return True


def generate_recovery_codes(count=8):
    # 12 hexadecimal characters provide 48 bits of entropy per single-use code.
    return [secrets.token_hex(6).upper() for _ in range(count)]


def replace_recovery_codes(user, codes):
    MfaRecoveryCode.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    for code in codes:
        user.recovery_codes.append(
            MfaRecoveryCode(code_hash=password_hasher.hash(code))
        )


def consume_recovery_code(user, presented_code):
    if not isinstance(presented_code, str):
        return False

    candidate = presented_code.strip().upper()
    if not candidate:
        return False

    unused = MfaRecoveryCode.query.filter_by(user_id=user.id, used_at=None).all()
    for record in unused:
        try:
            if password_hasher.verify(record.code_hash, candidate):
                record.used_at = utcnow()
                return True
        except (VerifyMismatchError, InvalidHashError):
            continue
    return False


def verify_second_factor(user, data, allow_recovery=True):
    code = data.get("code")
    if code and verify_totp(user, code, consume=True):
        return "totp"

    if allow_recovery and data.get("recovery_code"):
        if consume_recovery_code(user, data["recovery_code"]):
            return "recovery"

    return None
