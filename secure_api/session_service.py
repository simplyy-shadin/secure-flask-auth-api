from uuid import uuid4

from flask import current_app
from flask_jwt_extended import create_access_token, create_refresh_token, decode_token

from .extensions import db
from .models import AuthSession, utcnow
from .security import safe_user_agent, source_ip


def create_session(user, mfa_authenticated=False):
    active_sessions = AuthSession.query.filter_by(
        user_id=user.id,
        revoked_at=None,
    ).order_by(AuthSession.created_at.asc()).all()
    active_sessions = [session for session in active_sessions if session.is_valid()]

    max_sessions = current_app.config["MAX_ACTIVE_SESSIONS"]
    revoke_count = max(0, len(active_sessions) - max_sessions + 1)
    revoked_ids = []
    for old_session in active_sessions[:revoke_count]:
        old_session.revoke("session_limit")
        revoked_ids.append(old_session.id)

    session = AuthSession(
        id=str(uuid4()),
        user_id=user.id,
        refresh_jti=str(uuid4()),
        expires_at=utcnow() + current_app.config["JWT_REFRESH_TOKEN_EXPIRES"],
        source_ip=source_ip(),
        user_agent=safe_user_agent(),
        mfa_authenticated=mfa_authenticated,
    )
    db.session.add(session)
    return session, revoked_ids


def issue_access_token(user, session, fresh=False):
    return create_access_token(
        identity=str(user.id),
        additional_claims={"sid": session.id},
        fresh=fresh,
    )


def issue_token_pair(user, session, fresh_access=False):
    access_token = issue_access_token(
        user,
        session,
        fresh=fresh_access,
    )
    remaining = session.expires_at - utcnow()
    refresh_token = create_refresh_token(
        identity=str(user.id),
        additional_claims={"sid": session.id},
        expires_delta=remaining,
    )
    session.refresh_jti = decode_token(refresh_token)["jti"]
    session.last_rotated_at = utcnow()
    return access_token, refresh_token


def revoke_sessions(user_id, reason, exclude_session_id=None):
    sessions = AuthSession.query.filter_by(user_id=user_id, revoked_at=None).all()
    count = 0
    for session in sessions:
        if exclude_session_id and session.id == exclude_session_id:
            continue
        if session.is_valid():
            session.revoke(reason)
            count += 1
    return count
