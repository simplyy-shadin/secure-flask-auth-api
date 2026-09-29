import json

from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required

from .models import AuditEvent


security_events_bp = Blueprint("security_events", __name__)


@security_events_bp.get("/security-events")
@jwt_required()
def security_events():
    try:
        requested_limit = int(request.args.get("limit", 20))
    except (TypeError, ValueError):
        return jsonify(error="Invalid limit", code="validation_error"), 400

    limit = min(max(requested_limit, 1), 100)
    user_id = int(get_jwt_identity())

    events = (
        AuditEvent.query.filter_by(user_id=user_id)
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .limit(limit)
        .all()
    )

    return jsonify(
        [
            {
                "event_type": event.event_type,
                "request_id": event.request_id,
                "source_ip": event.source_ip,
                "details": json.loads(event.details or "{}"),
                "created_at": event.created_at.isoformat() + "Z",
            }
            for event in events
        ]
    ), 200
