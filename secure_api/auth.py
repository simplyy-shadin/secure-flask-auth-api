from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import get_jwt, get_jwt_identity, jwt_required

from .audit import record_event
from .extensions import db, limiter
from .mfa import create_login_challenge, verify_second_factor
from .models import AuthSession, User
from .security import (
    dummy_password_check,
    lock_user_after_failure,
    normalize_email,
    normalize_username,
    validate_password,
    validate_username,
)
from .session_service import (
    create_session,
    issue_access_token,
    issue_token_pair,
    revoke_sessions,
)


auth_bp = Blueprint("auth", __name__)


def _json_body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None
    return data


@auth_bp.post("/register")
@limiter.limit("10 per hour")
def register():
    data = _json_body()
    if data is None:
        return jsonify(error="Invalid JSON body", code="invalid_request"), 400

    username = normalize_username(data.get("username"))
    password = data.get("password")
    try:
        email = normalize_email(data.get("email"))
        validate_username(username)
        validate_password(password, username=username, email=email)
    except ValueError as exc:
        return jsonify(error=str(exc), code="validation_error"), 400

    if User.query.filter(
        (User.username == username) | (User.email == email)
    ).first():
        return jsonify(
            error="Account cannot be created with those details",
            code="conflict",
        ), 409

    user = User(username=username, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    record_event("AUTH_REGISTER_SUCCESS", user_id=user.id)

    return jsonify(message="User registered successfully"), 201


@auth_bp.post("/login")
@limiter.limit("5 per minute;20 per hour")
def login():
    data = _json_body()
    if data is None:
        return jsonify(error="Invalid JSON body", code="invalid_request"), 400

    username = normalize_username(data.get("username"))
    password = data.get("password")
    if not username or not isinstance(password, str):
        return jsonify(
            error="Invalid credentials",
            code="authentication_failed",
        ), 401

    user = User.query.filter_by(username=username).first()
    if user is None:
        dummy_password_check(password)
        record_event(
            "AUTH_LOGIN_FAILURE",
            details={"reason": "invalid_credentials"},
        )
        return jsonify(
            error="Invalid credentials",
            code="authentication_failed",
        ), 401

    if not user.is_active:
        dummy_password_check(password)
        record_event(
            "AUTH_LOGIN_FAILURE",
            user_id=user.id,
            details={"reason": "inactive"},
        )
        return jsonify(
            error="Invalid credentials",
            code="authentication_failed",
        ), 401

    if user.is_locked():
        record_event("AUTH_LOGIN_BLOCKED", user_id=user.id)
        return jsonify(
            error="Invalid credentials",
            code="authentication_failed",
        ), 401

    if not user.check_password(password):
        lock_user_after_failure(user)
        db.session.commit()
        record_event(
            "AUTH_LOGIN_FAILURE",
            user_id=user.id,
            details={"reason": "invalid_credentials"},
        )
        return jsonify(
            error="Invalid credentials",
            code="authentication_failed",
        ), 401

    user.failed_login_count = 0
    user.locked_until = None

    if user.mfa_enabled:
        challenge, mfa_token = create_login_challenge(user)
        db.session.commit()
        record_event(
            "AUTH_MFA_CHALLENGE_ISSUED",
            user_id=user.id,
            details={"challenge_id": challenge.id},
        )
        return jsonify(
            mfa_required=True,
            mfa_token=mfa_token,
            expires_in=current_app.config["MFA_CHALLENGE_MINUTES"] * 60,
        ), 202

    session, revoked_ids = create_session(user, mfa_authenticated=False)
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
        "AUTH_LOGIN_SUCCESS",
        user_id=user.id,
        details={"session_id": session.id},
    )

    return jsonify(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="Bearer",
        expires_in=int(
            current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()
        ),
    )


@auth_bp.post("/refresh")
@jwt_required(refresh=True, skip_revocation_check=True)
@limiter.limit("30 per hour")
def refresh():
    claims = get_jwt()
    user_id = int(get_jwt_identity())
    session_id = claims.get("sid")
    presented_jti = claims.get("jti")

    session = db.session.get(AuthSession, session_id) if session_id else None
    user = db.session.get(User, user_id)

    if (
        session is None
        or user is None
        or not user.is_active
        or session.user_id != user_id
        or not session.is_valid()
    ):
        record_event(
            "AUTH_REFRESH_REJECTED",
            user_id=user_id,
            details={"reason": "invalid_session"},
        )
        return jsonify(
            error="Refresh token is no longer valid",
            code="token_revoked",
        ), 401

    if session.refresh_jti != presented_jti:
        session.revoke("refresh_token_reuse")
        db.session.commit()
        record_event(
            "AUTH_REFRESH_REUSE_DETECTED",
            user_id=user_id,
            details={"session_id": session.id},
        )
        return jsonify(
            error="Refresh token reuse detected",
            code="token_reuse_detected",
        ), 401

    access_token, refresh_token = issue_token_pair(
        user,
        session,
        fresh_access=False,
    )
    db.session.commit()
    record_event(
        "AUTH_TOKEN_REFRESH",
        user_id=user.id,
        details={"session_id": session.id},
    )

    return jsonify(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="Bearer",
        expires_in=int(
            current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()
        ),
    )


@auth_bp.post("/reauth")
@jwt_required()
@limiter.limit("10 per hour")
def reauthenticate():
    data = _json_body()
    if data is None:
        return jsonify(error="Invalid JSON body", code="invalid_request"), 400

    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    session_id = get_jwt().get("sid")
    session = db.session.get(AuthSession, session_id) if session_id else None
    password = data.get("current_password")

    if (
        user is None
        or session is None
        or not isinstance(password, str)
        or not user.check_password(password)
    ):
        record_event("AUTH_REAUTH_FAILURE", user_id=user_id)
        return jsonify(
            error="Reauthentication failed",
            code="authentication_failed",
        ), 401

    factor = "password"
    if user.mfa_enabled:
        factor = verify_second_factor(user, data, allow_recovery=True)
        if factor is None:
            db.session.rollback()
            record_event("AUTH_REAUTH_FAILURE", user_id=user.id)
            return jsonify(
                error="Reauthentication failed",
                code="authentication_failed",
            ), 401

    access_token = issue_access_token(
        user,
        session,
        fresh=True,
    )
    db.session.commit()
    record_event(
        "AUTH_REAUTH_SUCCESS",
        user_id=user.id,
        details={"factor": factor},
    )
    return jsonify(
        access_token=access_token,
        token_type="Bearer",
        expires_in=int(
            current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()
        ),
    ), 200


@auth_bp.post("/logout")
@jwt_required()
def logout():
    user_id = int(get_jwt_identity())
    session_id = get_jwt().get("sid")
    session = db.session.get(AuthSession, session_id) if session_id else None
    if session and session.user_id == user_id:
        session.revoke("logout")
        db.session.commit()
        record_event(
            "AUTH_LOGOUT",
            user_id=user_id,
            details={"session_id": session.id},
        )
    return jsonify(message="Session revoked"), 200


@auth_bp.post("/logout-all")
@jwt_required(fresh=True)
def logout_all():
    user_id = int(get_jwt_identity())
    count = revoke_sessions(user_id, "logout_all")
    db.session.commit()
    record_event(
        "AUTH_LOGOUT_ALL",
        user_id=user_id,
        details={"revoked_sessions": count},
    )
    return jsonify(
        message="All sessions revoked",
        revoked_sessions=count,
    ), 200


@auth_bp.get("/sessions")
@jwt_required()
def sessions():
    user_id = int(get_jwt_identity())
    current_session_id = get_jwt().get("sid")
    active_sessions = AuthSession.query.filter_by(
        user_id=user_id,
        revoked_at=None,
    ).all()
    active_sessions = [
        session for session in active_sessions if session.is_valid()
    ]

    return jsonify(
        [
            {
                "id": session.id,
                "current": session.id == current_session_id,
                "created_at": session.created_at.isoformat() + "Z",
                "last_rotated_at": session.last_rotated_at.isoformat() + "Z",
                "expires_at": session.expires_at.isoformat() + "Z",
                "source_ip": session.source_ip,
                "user_agent": session.user_agent,
                "mfa_authenticated": session.mfa_authenticated,
            }
            for session in active_sessions
        ]
    )


@auth_bp.delete("/sessions/<string:session_id>")
@jwt_required(fresh=True)
def revoke_session(session_id):
    user_id = int(get_jwt_identity())
    session = db.session.get(AuthSession, session_id)
    if session is None or session.user_id != user_id:
        return jsonify(error="Session not found", code="not_found"), 404

    session.revoke("user_revoked")
    db.session.commit()
    record_event(
        "AUTH_SESSION_REVOKED",
        user_id=user_id,
        details={"session_id": session.id},
    )
    return jsonify(message="Session revoked"), 200


@auth_bp.put("/password")
@jwt_required(fresh=True)
@limiter.limit("5 per hour")
def change_password():
    data = _json_body()
    if data is None:
        return jsonify(error="Invalid JSON body", code="invalid_request"), 400

    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    current_password = data.get("current_password")
    new_password = data.get("new_password")

    if (
        not user
        or not isinstance(current_password, str)
        or not user.check_password(current_password)
    ):
        record_event("AUTH_PASSWORD_CHANGE_FAILURE", user_id=user_id)
        return jsonify(
            error="Current password is incorrect",
            code="authentication_failed",
        ), 401

    try:
        validate_password(
            new_password,
            username=user.username,
            email=user.email,
        )
    except ValueError as exc:
        return jsonify(error=str(exc), code="validation_error"), 400

    user.set_password(new_password)
    revoked = revoke_sessions(user.id, "password_changed")
    db.session.commit()
    record_event(
        "AUTH_PASSWORD_CHANGED",
        user_id=user.id,
        details={"revoked_sessions": revoked},
    )
    return jsonify(message="Password changed. Sign in again."), 200
