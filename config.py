import os
from datetime import timedelta

from dotenv import load_dotenv


load_dotenv()


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "sqlite:///users.db",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=10)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)
    JWT_TOKEN_LOCATION = ["headers"]

    MAX_CONTENT_LENGTH = 16 * 1024
    RATELIMIT_STORAGE_URI = os.getenv(
        "RATELIMIT_STORAGE_URI",
        "memory://",
    )
    RATELIMIT_HEADERS_ENABLED = True

    PASSWORD_MIN_LENGTH = 12
    PASSWORD_MAX_LENGTH = 128
    AUTH_LOCK_THRESHOLD = 5
    AUTH_LOCK_MINUTES = 5
    APP_ENV = os.getenv("APP_ENV", "development")


class TestingConfig(Config):
    TESTING = True
    SECRET_KEY = "test-secret-key-that-is-long-enough-for-tests"
    JWT_SECRET_KEY = "test-jwt-secret-that-is-long-enough-for-tests"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    RATELIMIT_ENABLED = False


def validate_runtime_secrets(app):
    if app.config.get("TESTING"):
        return

    weak_values = {
        None,
        "",
        "your-secret-key",
        "your-jwt-secret",
        "change-me",
        "changeme",
    }
    for name in ("SECRET_KEY", "JWT_SECRET_KEY"):
        value = app.config.get(name)
        if (
            value in weak_values
            or not isinstance(value, str)
            or len(value) < 32
            or value.startswith("replace-with-")
        ):
            raise RuntimeError(
                f"{name} must be set to a unique random value "
                "of at least 32 characters"
            )
