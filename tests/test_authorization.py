from .conftest import login


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


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


def test_admin_can_list_users(client, user, admin):
    token = login(
        client,
        username="admin",
        password="AdministrativePassphrase!42",
    ).get_json()["access_token"]
    response = client.get(
        "/users",
        headers=bearer(token),
    )
    assert response.status_code == 200
    assert len(response.get_json()) >= 2


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
