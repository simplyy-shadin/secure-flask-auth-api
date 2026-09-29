from datetime import timedelta
from uuid import uuid4

from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import (
    create_access_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
)
from sqlalchemy import update

from .audit import record_event
from .extensions import db, limiter
from .mfa import (
    encrypt_secret,
    generate_recovery_codes,
    generate_totp_secret,
    provisioning_uri,
    replace_recovery_codes,
    verify_second_factor,
    verify_totp,
)
from .models import MfaChallenge, MfaRecoveryCode, User, utcnow
from .security import source_ip
from .session_service import create_session, issue_token_pair, revoke_sessions


mfa_bp = Blueprint("mfa", __name__)


def _json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


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


@mfa_bp.post("/mfa/verify-login")
@jwt_required(skip_revocation_check=True)
@limiter.limit("10 per minute")
def verify_login_mfa():
    claims = get_jwt()
    if claims.get("stage") != "mfa_login" or not claims.get("cid"):
        return jsonify(error="Invalid MFA challenge", code="invalid_mfa_challenge"), 401

    try:
        user_id = int(get_jwt_identity())
    except (TypeError, ValueError):
        return jsonify(error="Invalid MFA challenge", code="invalid_mfa_challenge"), 401

    challenge = db.session.get(MfaChallenge, claims["cid"])
    user = db.session.get(User, user_id)
    max_attempts = current_app.config["MFA_CHALLENGE_MAX_ATTEMPTS"]

    if (
        challenge is None
        or user is None
        or not user.is_active
        or not user.mfa_enabled
        or challenge.user_id != user_id
        or not challenge.is_valid(max_attempts)
    ):
        return jsonify(error="Invalid MFA challenge", code="invalid_mfa_challenge"), 401

    data = _json_body()
    if data is None:
        return jsonify(error="Invalid JSON body", code="invalid_request"), 400

    factor = verify_second_factor(user, data, allow_recovery=True)
    if factor is None:
        challenge.attempts += 1
        if challenge.attempts >= max_attempts:
            challenge.consumed_at = utcnow()
        db.session.commit()
        record_event(
            "AUTH_MFA_FAILURE",
            user_id=user.id,
            details={"challenge_id": challenge.id},
        )
        return jsonify(error="Invalid verification code", code="mfa_failed"), 401

    # Claim the challenge atomically so concurrent/replayed requests cannot both
    # create authenticated sessions.
    claimed = db.session.execute(
        update(MfaChallenge)
        .where(
            MfaChallenge.id == challenge.id,
            MfaChallenge.consumed_at.is_(None),
            MfaChallenge.expires_at > utcnow(),
            MfaChallenge.attempts < max_attempts,
        )
        .values(consumed_at=utcnow())
    ).rowcount

    if claimed != 1:
        db.session.rollback()
        return jsonify(error="Invalid MFA challenge", code="invalid_mfa_challenge"), 401

    session, revoked_ids = create_session(user, mfa_authenticated=True)
    access_token, refresh_token = issue_token_pair(
        user,
        session,
        fresh_access=True,
    )
    db.session.commit()

    if revoked_ids:
        record_event(
            "AUTH_SESSION_LIMIT_ENFORCED",
            user_id=user.id,
            details={"revoked_sessions": len(revoked_ids)},
        )
    record_event(
        "AUTH_MFA_SUCCESS",
        user_id=user.id,
        details={
            "factor": factor,
            "session_id": session.id,
        },
    )

    return jsonify(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="Bearer",
        expires_in=int(
            current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()
        ),
    ), 200


@mfa_bp.get("/mfa/status")
@jwt_required()
def mfa_status():
    user = db.session.get(User, int(get_jwt_identity()))
    remaining = 0
    if user and user.mfa_enabled:
        remaining = MfaRecoveryCode.query.filter_by(
            user_id=user.id,
            used_at=None,
        ).count()

    return jsonify(
        enabled=bool(user and user.mfa_enabled),
        recovery_codes_remaining=remaining,
    ), 200


@mfa_bp.post("/mfa/setup")
@jwt_required(fresh=True)
@limiter.limit("5 per hour")
def setup_mfa():
    user = db.session.get(User, int(get_jwt_identity()))
    data = _json_body()
    if user is None or data is None:
        return jsonify(error="Invalid request", code="invalid_request"), 400
    if user.mfa_enabled:
        return jsonify(error="MFA is already enabled", code="conflict"), 409

    password = data.get("current_password")
    if not isinstance(password, str) or not user.check_password(password):
        record_event("AUTH_MFA_SETUP_FAILURE", user_id=user.id)
        return jsonify(
            error="Current password is incorrect",
            code="authentication_failed",
        ), 401

    secret = generate_totp_secret()
    user.mfa_secret_encrypted = encrypt_secret(secret)
    user.mfa_last_used_step = None
    MfaRecoveryCode.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    db.session.commit()
    record_event("AUTH_MFA_SETUP_STARTED", user_id=user.id)

    return jsonify(
        manual_secret=secret,
        provisioning_uri=provisioning_uri(user, secret),
    ), 200


@mfa_bp.post("/mfa/enable")
@jwt_required(fresh=True)
@limiter.limit("10 per hour")
def enable_mfa():
    user = db.session.get(User, int(get_jwt_identity()))
    data = _json_body()
    if user is None or data is None or not user.mfa_secret_encrypted:
        return jsonify(error="MFA setup is required", code="mfa_setup_required"), 400
    if user.mfa_enabled:
        return jsonify(error="MFA is already enabled", code="conflict"), 409

    if not verify_totp(user, data.get("code"), consume=True):
        db.session.rollback()
        record_event("AUTH_MFA_ENABLE_FAILURE", user_id=user.id)
        return jsonify(error="Invalid verification code", code="mfa_failed"), 401

    user.mfa_enabled = True
    codes = generate_recovery_codes(
        current_app.config["MFA_RECOVERY_CODE_COUNT"]
    )
    replace_recovery_codes(user, codes)

    # Eliminate sessions created before MFA was enabled so all future sessions
    # must satisfy the new second factor.
    revoked = revoke_sessions(user.id, "mfa_enabled")
    db.session.commit()
    record_event(
        "AUTH_MFA_ENABLED",
        user_id=user.id,
        details={"revoked_sessions": revoked},
    )

    return jsonify(
        message="MFA enabled. Sign in again.",
        recovery_codes=codes,
    ), 200


@mfa_bp.post("/mfa/recovery-codes")
@jwt_required(fresh=True)
@limiter.limit("5 per hour")
def regenerate_recovery_codes():
    user = db.session.get(User, int(get_jwt_identity()))
    data = _json_body()
    if user is None or data is None or not user.mfa_enabled:
        return jsonify(error="MFA is not enabled", code="mfa_not_enabled"), 400

    password = data.get("current_password")
    if not isinstance(password, str) or not user.check_password(password):
        return jsonify(
            error="Current password is incorrect",
            code="authentication_failed",
        ), 401
    if not verify_totp(user, data.get("code"), consume=True):
        db.session.rollback()
        return jsonify(error="Invalid verification code", code="mfa_failed"), 401

    codes = generate_recovery_codes(
        current_app.config["MFA_RECOVERY_CODE_COUNT"]
    )
    replace_recovery_codes(user, codes)
    db.session.commit()
    record_event("AUTH_MFA_RECOVERY_CODES_REGENERATED", user_id=user.id)

    return jsonify(recovery_codes=codes), 200


@mfa_bp.post("/mfa/disable")
@jwt_required(fresh=True)
@limiter.limit("5 per hour")
def disable_mfa():
    user = db.session.get(User, int(get_jwt_identity()))
    data = _json_body()
    if user is None or data is None or not user.mfa_enabled:
        return jsonify(error="MFA is not enabled", code="mfa_not_enabled"), 400

    password = data.get("current_password")
    if not isinstance(password, str) or not user.check_password(password):
        return jsonify(
            error="Current password is incorrect",
            code="authentication_failed",
        ), 401

    factor = verify_second_factor(user, data, allow_recovery=True)
    if factor is None:
        db.session.rollback()
        return jsonify(error="Invalid verification code", code="mfa_failed"), 401

    user.mfa_enabled = False
    user.mfa_secret_encrypted = None
    user.mfa_last_used_step = None
    MfaRecoveryCode.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    revoked = revoke_sessions(user.id, "mfa_disabled")
    db.session.commit()
    record_event(
        "AUTH_MFA_DISABLED",
        user_id=user.id,
        details={
            "factor": factor,
            "revoked_sessions": revoked,
        },
    )

    return jsonify(message="MFA disabled. Sign in again."), 200
