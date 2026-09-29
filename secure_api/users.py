from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy.exc import IntegrityError

from .audit import record_event
from .extensions import db
from .models import User
from .security import normalize_email


users_bp = Blueprint("users", __name__)


def _current_user():
    identity = get_jwt_identity()
    try:
        return db.session.get(User, int(identity))
    except (TypeError, ValueError):
        return None


def _serialize_user(user):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "mfa_enabled": user.mfa_enabled,
        "created_at": user.created_at.isoformat() + "Z",
    }


def _is_admin(user):
    return user is not None and user.role == "admin"


@users_bp.get("/profile")
@jwt_required()
def profile():
    user = _current_user()
    if user is None or not user.is_active:
        return jsonify(error="User not found", code="not_found"), 404
    return jsonify(_serialize_user(user)), 200


@users_bp.get("/users")
@jwt_required()
def get_users():
    current = _current_user()
    if not _is_admin(current):
        record_event(
            "AUTHORIZATION_DENIED",
            user_id=current.id if current else None,
            details={"resource": "users"},
        )
        return jsonify(error="Forbidden", code="forbidden"), 403

    users = User.query.order_by(User.id).all()
    return jsonify([_serialize_user(user) for user in users]), 200


@users_bp.get("/users/<int:user_id>")
@jwt_required()
def get_user(user_id):
    current = _current_user()
    if current is None:
        return jsonify(error="User not found", code="not_found"), 404
    if not _is_admin(current) and current.id != user_id:
        record_event(
            "AUTHORIZATION_DENIED",
            user_id=current.id,
            details={
                "resource": "user",
                "target_user_id": user_id,
            },
        )
        return jsonify(error="Forbidden", code="forbidden"), 403

    user = db.session.get(User, user_id)
    if user is None:
        return jsonify(error="User not found", code="not_found"), 404
    return jsonify(_serialize_user(user)), 200


@users_bp.put("/users/<int:user_id>")
@jwt_required(fresh=True)
def update_user(user_id):
    current = _current_user()
    if current is None:
        return jsonify(error="User not found", code="not_found"), 404
    if not _is_admin(current) and current.id != user_id:
        record_event(
            "AUTHORIZATION_DENIED",
            user_id=current.id,
            details={
                "resource": "user_update",
                "target_user_id": user_id,
            },
        )
        return jsonify(error="Forbidden", code="forbidden"), 403

    user = db.session.get(User, user_id)
    if user is None:
        return jsonify(error="User not found", code="not_found"), 404

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Invalid JSON body", code="invalid_request"), 400

    is_self_change = current.id == user.id
    allowed_fields = {"email", "current_password"} if is_self_change else {"email"}
    if set(data) - allowed_fields:
        return jsonify(
            error="Only email can be updated here",
            code="validation_error",
        ), 400
    if "email" not in data:
        return jsonify(error="Email is required", code="validation_error"), 400

    if is_self_change:
        password = data.get("current_password")
        if not isinstance(password, str) or not current.check_password(password):
            record_event("USER_EMAIL_CHANGE_FAILURE", user_id=current.id)
            return jsonify(
                error="Current password is incorrect",
                code="authentication_failed",
            ), 401

    try:
        email = normalize_email(data["email"])
    except ValueError as exc:
        return jsonify(error=str(exc), code="validation_error"), 400

    conflict = User.query.filter(
        User.email == email,
        User.id != user.id,
    ).first()
    if conflict:
        return jsonify(error="Email cannot be used", code="conflict"), 409

    user.email = email
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify(error="Email cannot be used", code="conflict"), 409

    record_event(
        "USER_EMAIL_UPDATED",
        user_id=current.id,
        details={"target_user_id": user.id},
    )
    return jsonify(message="User updated successfully"), 200


@users_bp.delete("/users/<int:user_id>")
@jwt_required(fresh=True)
def delete_user(user_id):
    current = _current_user()
    if not _is_admin(current):
        record_event(
            "AUTHORIZATION_DENIED",
            user_id=current.id if current else None,
            details={
                "resource": "user_delete",
                "target_user_id": user_id,
            },
        )
        return jsonify(error="Forbidden", code="forbidden"), 403

    user = db.session.get(User, user_id)
    if user is None:
        return jsonify(error="User not found", code="not_found"), 404

    db.session.delete(user)
    db.session.commit()
    record_event(
        "ADMIN_USER_DELETED",
        user_id=current.id,
        details={"target_user_id": user_id},
    )
    return jsonify(message="User deleted successfully"), 200
