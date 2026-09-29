import logging
from uuid import uuid4

import click
from flask import Flask, g, jsonify

from config import Config, validate_runtime_secrets
from .auth import auth_bp
from .extensions import db, jwt, limiter, migrate
from .mfa_routes import mfa_bp
from .models import AuthSession, User
from .security import (
    normalize_email,
    normalize_username,
    validate_password,
    validate_username,
)
from .security_events import security_events_bp
from .users import users_bp


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)
    validate_runtime_secrets(app)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    db.init_app(app)
    jwt.init_app(app)
    limiter.init_app(app)
    migrate.init_app(
        app,
        db,
        compare_type=True,
        render_as_batch=True,
    )

    app.register_blueprint(auth_bp)
    app.register_blueprint(mfa_bp)
    app.register_blueprint(security_events_bp)
    app.register_blueprint(users_bp)

    @app.before_request
    def attach_request_id():
        g.request_id = str(uuid4())

    @app.after_request
    def security_headers(response):
        response.headers["X-Request-ID"] = g.get(
            "request_id",
            str(uuid4()),
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
        )
        response.headers["Cache-Control"] = "no-store"
        if app.config.get("APP_ENV") == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response

    @app.get("/")
    def home():
        return jsonify(
            name="Secure Flask Authentication API",
            focus="Authentication, MFA, session, and API security",
            status="ok",
        )

    @app.get("/health")
    def health():
        return jsonify(status="healthy"), 200

    @jwt.token_in_blocklist_loader
    def token_is_revoked(jwt_header, jwt_payload):
        session_id = jwt_payload.get("sid")
        subject = jwt_payload.get("sub")
        if not session_id or not subject:
            return True
        try:
            user_id = int(subject)
        except (TypeError, ValueError):
            return True

        session = db.session.get(AuthSession, session_id)
        user = db.session.get(User, user_id)
        if (
            session is None
            or user is None
            or not user.is_active
            or session.user_id != user_id
            or not session.is_valid()
        ):
            return True

        if jwt_payload.get("type") == "refresh":
            return jwt_payload.get("jti") != session.refresh_jti
        return False

    @jwt.unauthorized_loader
    def missing_token(reason):
        return jsonify(
            error="Authentication required",
            code="authorization_required",
        ), 401

    @jwt.invalid_token_loader
    def invalid_token(reason):
        return jsonify(
            error="Invalid authentication token",
            code="invalid_token",
        ), 401

    @jwt.expired_token_loader
    def expired_token(jwt_header, jwt_payload):
        return jsonify(
            error="Authentication token expired",
            code="token_expired",
        ), 401

    @jwt.revoked_token_loader
    def revoked_token(jwt_header, jwt_payload):
        return jsonify(
            error="Authentication token revoked",
            code="token_revoked",
        ), 401

    @jwt.needs_fresh_token_loader
    def fresh_token_required(jwt_header, jwt_payload):
        return jsonify(
            error="Recent authentication is required",
            code="fresh_token_required",
        ), 401

    @app.errorhandler(404)
    def not_found(error):
        return jsonify(error="Resource not found", code="not_found"), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify(
            error="Method not allowed",
            code="method_not_allowed",
        ), 405

    @app.errorhandler(413)
    def request_too_large(error):
        return jsonify(
            error="Request body too large",
            code="request_too_large",
        ), 413

    @app.errorhandler(429)
    def rate_limited(error):
        return jsonify(error="Too many requests", code="rate_limited"), 429

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        app.logger.exception("Unhandled application error")
        return jsonify(
            error="Internal server error",
            code="internal_error",
        ), 500

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    @click.option("--email", prompt=True)
    @click.password_option(confirmation_prompt=True)
    def create_admin_command(username, email, password):
        username = normalize_username(username)
        email = normalize_email(email)
        validate_username(username)
        validate_password(
            password,
            username=username,
            email=email,
        )
        existing = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing:
            raise click.ClickException("Username or email already exists")
        user = User(
            username=username,
            email=email,
            role="admin",
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f"Admin user '{username}' created.")

    return app
