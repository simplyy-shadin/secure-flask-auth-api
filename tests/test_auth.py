from secure_api.extensions import db
from secure_api.models import User

from .conftest import login


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_register_normalizes_identifiers(client):
    response = client.post(
        "/register",
        json={
            "username": "New.User",
            "email": "New.User@Example.COM",
            "password": "LongUniquePassphrase!2026",
        },
    )
    assert response.status_code == 201

    signed_in = client.post(
        "/login",
        json={
            "username": "new.user",
            "password": "LongUniquePassphrase!2026",
        },
    )
    assert signed_in.status_code == 200


def test_registration_does_not_reveal_duplicate_field(client, user):
    response = client.post(
        "/register",
        json={
            "username": "different",
            "email": "alice@example.com",
            "password": "UnrelatedStrongPassphrase!2026",
        },
    )
    assert response.status_code == 409
    assert "email" not in response.get_json()["error"].lower()


def test_registration_rejects_invalid_security_inputs(client):
    cases = [
        {
            "username": "x",
            "email": "valid@example.com",
            "password": "LongUniquePassphrase!2026",
        },
        {
            "username": "valid-user",
            "email": "not-an-email",
            "password": "LongUniquePassphrase!2026",
        },
        {
            "username": "valid-user",
            "email": "valid@example.com",
            "password": "short",
        },
        {
            "username": "valid-user",
            "email": "valid@example.com",
            "password": "valid-user-is-inside-this-password",
        },
        {
            "username": "valid-user",
            "email": "identity@example.com",
            "password": "identity-is-inside-this-password",
        },
    ]
    for payload in cases:
        response = client.post("/register", json=payload)
        assert response.status_code == 400
        assert response.get_json()["code"] == "validation_error"


def test_login_returns_access_and_refresh_tokens(client, user):
    response = login(client)
    assert response.status_code == 200
    body = response.get_json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["token_type"] == "Bearer"


def test_login_uses_generic_failure_for_unknown_or_inactive_users(
    client,
    app,
    user,
):
    unknown = client.post(
        "/login",
        json={"username": "ghost", "password": "anything"},
    )
    assert unknown.status_code == 401
    assert unknown.get_json()["error"] == "Invalid credentials"

    with app.app_context():
        account = db.session.get(User, user)
        account.is_active = False
        db.session.commit()

    inactive = login(client)
    assert inactive.status_code == 401
    assert inactive.get_json()["error"] == "Invalid credentials"


def test_login_rejects_invalid_json_and_missing_credentials(client):
    malformed = client.post(
        "/login",
        data="not-json",
        content_type="application/json",
    )
    assert malformed.status_code == 400

    missing = client.post("/login", json={"username": "alice"})
    assert missing.status_code == 401
    assert missing.get_json()["code"] == "authentication_failed"


def test_refresh_rotation_rejects_replayed_refresh_token(client, user):
    signed_in = login(client).get_json()
    old_refresh = signed_in["refresh_token"]

    rotated = client.post(
        "/refresh",
        headers=bearer(old_refresh),
    )
    assert rotated.status_code == 200
    new_access = rotated.get_json()["access_token"]

    replay = client.post(
        "/refresh",
        headers=bearer(old_refresh),
    )
    assert replay.status_code == 401
    assert replay.get_json()["code"] == "token_reuse_detected"

    profile = client.get(
        "/profile",
        headers=bearer(new_access),
    )
    assert profile.status_code == 401


def test_logout_revokes_entire_session(client, user):
    tokens = login(client).get_json()
    access = tokens["access_token"]
    refresh = tokens["refresh_token"]

    assert client.post(
        "/logout",
        headers=bearer(access),
    ).status_code == 200
    assert client.get(
        "/profile",
        headers=bearer(access),
    ).status_code == 401
    assert client.post(
        "/refresh",
        headers=bearer(refresh),
    ).status_code == 401


def test_logout_all_revokes_parallel_sessions(client, user):
    first = login(client).get_json()
    second = login(client).get_json()

    response = client.post(
        "/logout-all",
        headers=bearer(first["access_token"]),
    )
    assert response.status_code == 200
    assert response.get_json()["revoked_sessions"] == 2
    assert client.get(
        "/profile",
        headers=bearer(second["access_token"]),
    ).status_code == 401


def test_password_change_revokes_all_sessions(client, user):
    first = login(client).get_json()
    second = login(client).get_json()

    response = client.put(
        "/password",
        headers=bearer(first["access_token"]),
        json={
            "current_password": "CorrectHorseBatteryStaple!42",
            "new_password": "FreshStrongPassphrase!2026",
        },
    )
    assert response.status_code == 200
    assert client.get(
        "/profile",
        headers=bearer(second["access_token"]),
    ).status_code == 401

    relogin = client.post(
        "/login",
        json={
            "username": "alice",
            "password": "FreshStrongPassphrase!2026",
        },
    )
    assert relogin.status_code == 200


def test_password_change_rejects_wrong_or_weak_password(client, user):
    token = login(client).get_json()["access_token"]

    wrong = client.put(
        "/password",
        headers=bearer(token),
        json={
            "current_password": "incorrect",
            "new_password": "AnotherStrongPassphrase!2026",
        },
    )
    assert wrong.status_code == 401

    weak = client.put(
        "/password",
        headers=bearer(token),
        json={
            "current_password": "CorrectHorseBatteryStaple!42",
            "new_password": "short",
        },
    )
    assert weak.status_code == 400

    malformed = client.put(
        "/password",
        headers=bearer(token),
        data="not-json",
        content_type="application/json",
    )
    assert malformed.status_code == 400


def test_account_temporarily_locks_after_repeated_failures(client, user):
    for _ in range(5):
        response = client.post(
            "/login",
            json={
                "username": "alice",
                "password": "wrong-password",
            },
        )
        assert response.status_code == 401

    blocked = login(client)
    assert blocked.status_code == 401
    assert blocked.get_json()["code"] == "authentication_failed"
