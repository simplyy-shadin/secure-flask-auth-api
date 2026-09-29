from .conftest import login


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def admin_token(client):
    return login(
        client,
        username="admin",
        password="AdministrativePassphrase!42",
    ).get_json()["access_token"]


def test_user_can_read_own_profile_and_record(client, user):
    token = login(client).get_json()["access_token"]

    profile = client.get("/profile", headers=bearer(token))
    assert profile.status_code == 200
    assert profile.get_json()["id"] == user

    record = client.get(f"/users/{user}", headers=bearer(token))
    assert record.status_code == 200
    assert record.get_json()["username"] == "alice"


def test_user_cannot_read_another_users_record(
    client,
    user,
    second_user,
):
    token = login(client).get_json()["access_token"]
    response = client.get(
        f"/users/{second_user}",
        headers=bearer(token),
    )
    assert response.status_code == 403


def test_user_cannot_list_all_users(client, user):
    token = login(client).get_json()["access_token"]
    response = client.get(
        "/users",
        headers=bearer(token),
    )
    assert response.status_code == 403


def test_admin_can_list_and_read_users(client, user, admin):
    token = admin_token(client)
    response = client.get(
        "/users",
        headers=bearer(token),
    )
    assert response.status_code == 200
    assert len(response.get_json()) >= 2

    record = client.get(
        f"/users/{user}",
        headers=bearer(token),
    )
    assert record.status_code == 200


def test_user_cannot_update_another_users_email(
    client,
    user,
    second_user,
):
    token = login(client).get_json()["access_token"]
    response = client.put(
        f"/users/{second_user}",
        headers=bearer(token),
        json={"email": "stolen@example.com"},
    )
    assert response.status_code == 403


def test_user_can_update_own_email_with_password_confirmation(client, user):
    token = login(client).get_json()["access_token"]
    response = client.put(
        f"/users/{user}",
        headers=bearer(token),
        json={
            "email": "alice.new@example.com",
            "current_password": "CorrectHorseBatteryStaple!42",
        },
    )
    assert response.status_code == 200

    profile = client.get("/profile", headers=bearer(token))
    assert profile.get_json()["email"] == "alice.new@example.com"


def test_self_email_change_rejects_wrong_password(client, user):
    token = login(client).get_json()["access_token"]
    response = client.put(
        f"/users/{user}",
        headers=bearer(token),
        json={
            "email": "alice.new@example.com",
            "current_password": "incorrect",
        },
    )
    assert response.status_code == 401
    assert response.get_json()["code"] == "authentication_failed"


def test_email_update_rejects_conflict_invalid_and_empty_payload(
    client,
    user,
    second_user,
):
    token = login(client).get_json()["access_token"]
    password = "CorrectHorseBatteryStaple!42"

    conflict = client.put(
        f"/users/{user}",
        headers=bearer(token),
        json={
            "email": "bob@example.com",
            "current_password": password,
        },
    )
    assert conflict.status_code == 409

    invalid = client.put(
        f"/users/{user}",
        headers=bearer(token),
        json={
            "email": "not-email",
            "current_password": password,
        },
    )
    assert invalid.status_code == 400

    empty = client.put(
        f"/users/{user}",
        headers=bearer(token),
        json={},
    )
    assert empty.status_code == 400


def test_user_cannot_submit_role_field_for_self_escalation(
    client,
    user,
):
    token = login(client).get_json()["access_token"]
    response = client.put(
        f"/users/{user}",
        headers=bearer(token),
        json={"role": "admin"},
    )
    assert response.status_code == 400


def test_admin_can_update_other_users_email_without_target_password(
    client,
    user,
    admin,
):
    token = admin_token(client)
    response = client.put(
        f"/users/{user}",
        headers=bearer(token),
        json={"email": "managed@example.com"},
    )
    assert response.status_code == 200


def test_only_admin_can_delete_user(client, user, second_user, admin):
    user_access = login(client).get_json()["access_token"]
    denied = client.delete(
        f"/users/{second_user}",
        headers=bearer(user_access),
    )
    assert denied.status_code == 403

    admin_access = admin_token(client)
    deleted = client.delete(
        f"/users/{second_user}",
        headers=bearer(admin_access),
    )
    assert deleted.status_code == 200

    missing = client.get(
        f"/users/{second_user}",
        headers=bearer(admin_access),
    )
    assert missing.status_code == 404


def test_admin_delete_missing_user_returns_not_found(client, admin):
    response = client.delete(
        "/users/99999",
        headers=bearer(admin_token(client)),
    )
    assert response.status_code == 404
