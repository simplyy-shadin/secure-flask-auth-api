import re
from datetime import timedelta

from argon2 import PasswordHasher
from email_validator import EmailNotValidError, validate_email
from flask import current_app, request

from .models import utcnow


USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456789012",
    "qwerty123456",
    "letmein123456",
    "admin12345678",
}
_dummy_hasher = PasswordHasher()
_DUMMY_HASH = _dummy_hasher.hash("this-is-not-a-real-user-password")


def normalize_username(value):
    if not isinstance(value, str):
        return ""
    return value.strip().lower()


def normalize_email(value):
    if not isinstance(value, str):
        raise ValueError("Invalid email address")
    try:
        return validate_email(value.strip(), check_deliverability=False).normalized.lower()
    except EmailNotValidError as exc:
        raise ValueError("Invalid email address") from exc


def validate_username(username):
    if not USERNAME_RE.fullmatch(username):
        raise ValueError(
            "Username must be 3-32 characters and use only letters, numbers, ., _, or -"
        )


def validate_password(password, username="", email=""):
    if not isinstance(password, str):
        raise ValueError("Password is required")

    minimum = current_app.config["PASSWORD_MIN_LENGTH"]
    maximum = current_app.config["PASSWORD_MAX_LENGTH"]
    if len(password) < minimum:
        raise ValueError(f"Password must be at least {minimum} characters")
    if len(password) > maximum:
        raise ValueError(f"Password must be at most {maximum} characters")

    lowered = password.casefold()
    if lowered in COMMON_PASSWORDS:
        raise ValueError("Choose a less common password")
    if username and len(username) >= 3 and username.casefold() in lowered:
        raise ValueError("Password must not contain the username")
    local_part = email.split("@", 1)[0] if email else ""
    if len(local_part) >= 4 and local_part.casefold() in lowered:
        raise ValueError("Password must not contain the email name")


def dummy_password_check(password):
    try:
        _dummy_hasher.verify(_DUMMY_HASH, password or "")
    except Exception:
        pass


def lock_user_after_failure(user):
    user.failed_login_count += 1
    if user.failed_login_count >= current_app.config["AUTH_LOCK_THRESHOLD"]:
        user.locked_until = utcnow() + timedelta(
            minutes=current_app.config["AUTH_LOCK_MINUTES"]
        )
        user.failed_login_count = 0


def source_ip():
    return request.remote_addr


def safe_user_agent():
    value = request.user_agent.string or ""
    return value[:255]
