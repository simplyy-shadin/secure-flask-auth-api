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


def test_invalid_jwt_returns_controlled_error(client):
    response = client.get(
        "/profile",
        headers=bearer("not.a.valid.jwt"),
    )
    assert response.status_code == 401
    assert response.get_json()["code"] == "invalid_token"


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


def test_hsts_is_only_added_in_production_mode(client, app):
    assert "Strict-Transport-Security" not in client.get("/health").headers

    app.config["APP_ENV"] = "production"
    response = client.get("/health")
    assert "max-age=31536000" in response.headers[
        "Strict-Transport-Security"
    ]


def test_not_found_method_and_request_size_errors_are_json(client):
    missing = client.get("/does-not-exist")
    assert missing.status_code == 404
    assert missing.get_json()["code"] == "not_found"

    wrong_method = client.get("/login")
    assert wrong_method.status_code == 405
    assert wrong_method.get_json()["code"] == "method_not_allowed"

    oversized = client.post(
        "/register",
        data="x" * (17 * 1024),
        content_type="application/json",
    )
    assert oversized.status_code == 413
    assert oversized.get_json()["code"] == "request_too_large"


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


def test_user_cannot_revoke_unknown_session(client, user):
    token = login(client).get_json()["access_token"]
    response = client.delete(
        "/sessions/00000000-0000-0000-0000-000000000000",
        headers=bearer(token),
    )
    assert response.status_code == 404
