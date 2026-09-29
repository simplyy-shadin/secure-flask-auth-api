from .conftest import login


PASSWORD = "CorrectHorseBatteryStaple!42"


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_refreshed_access_token_cannot_perform_sensitive_action_until_reauth(
    client,
    user,
):
    tokens = login(client).get_json()
    refreshed = client.post(
        "/refresh",
        headers=bearer(tokens["refresh_token"]),
    )
    assert refreshed.status_code == 200
    non_fresh = refreshed.get_json()["access_token"]

    denied = client.put(
        "/password",
        headers=bearer(non_fresh),
        json={
            "current_password": PASSWORD,
            "new_password": "NewVeryStrongPassphrase!2026",
        },
    )
    assert denied.status_code == 401
    assert denied.get_json()["code"] == "fresh_token_required"

    reauth = client.post(
        "/reauth",
        headers=bearer(non_fresh),
        json={"current_password": PASSWORD},
    )
    assert reauth.status_code == 200

    changed = client.put(
        f"/users/{user}",
        headers=bearer(reauth.get_json()["access_token"]),
        json={
            "email": "alice.reauthed@example.com",
            "current_password": PASSWORD,
        },
    )
    assert changed.status_code == 200


def test_reauth_rejects_wrong_password(client, user):
    token = login(client).get_json()["access_token"]
    response = client.post(
        "/reauth",
        headers=bearer(token),
        json={"current_password": "wrong"},
    )
    assert response.status_code == 401


def test_session_cap_revokes_oldest_session(client, user):
    sessions = [login(client).get_json() for _ in range(6)]

    oldest = sessions[0]["access_token"]
    newest = sessions[-1]["access_token"]

    assert client.get("/profile", headers=bearer(oldest)).status_code == 401

    inventory = client.get("/sessions", headers=bearer(newest))
    assert inventory.status_code == 200
    assert len(inventory.get_json()) == 5


def test_security_event_history_returns_only_authenticated_users_events(
    client,
    user,
):
    token = login(client).get_json()["access_token"]

    events = client.get(
        "/security-events?limit=10",
        headers=bearer(token),
    )
    assert events.status_code == 200
    types = {item["event_type"] for item in events.get_json()}
    assert "AUTH_LOGIN_SUCCESS" in types

    invalid = client.get(
        "/security-events?limit=abc",
        headers=bearer(token),
    )
    assert invalid.status_code == 400


def test_refresh_and_access_tokens_cannot_be_substituted(client, user):
    tokens = login(client).get_json()

    access_on_refresh = client.post(
        "/refresh",
        headers=bearer(tokens["access_token"]),
    )
    assert access_on_refresh.status_code == 401

    refresh_on_profile = client.get(
        "/profile",
        headers=bearer(tokens["refresh_token"]),
    )
    assert refresh_on_profile.status_code == 401
