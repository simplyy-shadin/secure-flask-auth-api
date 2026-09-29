from .conftest import login


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_malformed_json_returns_controlled_error(client):
    response = client.post(
        "/register",
        data="not-json",
        content_type="application/json",
    )
    assert response.status_code == 400
    assert response.get_json()["code"] == "invalid_request"


def test_protected_endpoint_requires_authentication(client):
    response = client.get("/profile")
    assert response.status_code == 401
    assert response.get_json()["code"] == "authorization_required"


def test_security_headers_are_present(client):
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'none'" in response.headers[
        "Content-Security-Policy"
    ]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Request-ID"]


def test_session_inventory_and_manual_revocation(client, user):
    first = login(client).get_json()
    second = login(client).get_json()

    sessions = client.get(
        "/sessions",
        headers=bearer(first["access_token"]),
    )
    assert sessions.status_code == 200
    body = sessions.get_json()
    assert len(body) == 2

    other = next(item for item in body if not item["current"])
    revoked = client.delete(
        f"/sessions/{other['id']}",
        headers=bearer(first["access_token"]),
    )
    assert revoked.status_code == 200
    assert client.get(
        "/profile",
        headers=bearer(second["access_token"]),
    ).status_code == 401
