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
            "password": "DifferentStrongPassphrase!2026",
        },
    )
    assert response.status_code == 409
    assert "email" not in response.get_json()["error"].lower()


def test_login_returns_access_and_refresh_tokens(client, user):
    response = login(client)
    assert response.status_code == 200
    body = response.get_json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["token_type"] == "Bearer"


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
