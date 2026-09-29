import json
import logging

from flask import g, has_request_context

from .extensions import db
from .models import AuditEvent
from .security import source_ip


logger = logging.getLogger("secure_api.audit")


def record_event(event_type, user_id=None, details=None):
    request_id = (
        getattr(g, "request_id", "no-request") if has_request_context() else "no-request"
    )
    ip = source_ip() if has_request_context() else None
    safe_details = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))

    event = AuditEvent(
        event_type=event_type,
        user_id=user_id,
        request_id=request_id,
        source_ip=ip,
        details=safe_details,
    )
    db.session.add(event)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        logger.exception("Failed to persist security audit event %s", event_type)

    logger.info(
        "security_event=%s user_id=%s request_id=%s source_ip=%s",
        event_type,
        user_id,
        request_id,
        ip,
    )
