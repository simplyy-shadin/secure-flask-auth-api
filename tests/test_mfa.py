from datetime import UTC, datetime

import pyotp

from .conftest import login


PASSWORD = "CorrectHorseBatteryStaple!42"


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def enable_mfa(client, access_token):
    setup = client.post(
        "/mfa/setup",
        headers=bearer(access_token),
        json={"current_password": PASSWORD},
    )
    assert setup.status_code == 200
    secret = setup.get_json()["manual_secret"]
    code = pyotp.TOTP(secret).now()

    enabled = client.post(
        "/mfa/enable",
        headers=bearer(access_token),
        json={"code": code},
    )
    assert enabled.status_code == 200
    return secret, enabled.get_json()["recovery_codes"]


def begin_mfa_login(client):
    response = login(client)
    assert response.status_code == 202
    body = response.get_json()
    assert body["mfa_required"] is True
    return body["mfa_token"]


def test_mfa_enrollment_forces_future_two_factor_login(client, user):
    access = login(client).get_json()["access_token"]
    secret, recovery_codes = enable_mfa(client, access)

    assert len(recovery_codes) == 8
    assert len(set(recovery_codes)) == 8

    assert client.get("/profile", headers=bearer(access)).status_code == 401

    mfa_token = begin_mfa_login(client)
    totp = pyotp.TOTP(secret)
    next_step = totp.timecode(datetime.now(UTC)) + 1
    completed = client.post(
        "/mfa/verify-login",
        headers=bearer(mfa_token),
        json={"code": totp.generate_otp(next_step)},
    )
    assert completed.status_code == 200

    access = completed.get_json()["access_token"]
    status = client.get("/mfa/status", headers=bearer(access))
    assert status.status_code == 200
    assert status.get_json()["enabled"] is True
    assert status.get_json()["recovery_codes_remaining"] == 8

    sessions = client.get("/sessions", headers=bearer(access))
    assert sessions.get_json()[0]["mfa_authenticated"] is True


def test_mfa_challenge_is_single_use_even_with_another_valid_factor(client, user):
    access = login(client).get_json()["access_token"]
    _, recovery_codes = enable_mfa(client, access)

    mfa_token = begin_mfa_login(client)
    first = client.post(
        "/mfa/verify-login",
        headers=bearer(mfa_token),
        json={"recovery_code": recovery_codes[0]},
    )
    assert first.status_code == 200

    replay = client.post(
        "/mfa/verify-login",
        headers=bearer(mfa_token),
        json={"recovery_code": recovery_codes[1]},
    )
    assert replay.status_code == 401
    assert replay.get_json()["code"] == "invalid_mfa_challenge"


def test_recovery_code_is_single_use(client, user):
    access = login(client).get_json()["access_token"]
    _, recovery_codes = enable_mfa(client, access)

    first_challenge = begin_mfa_login(client)
    first = client.post(
        "/mfa/verify-login",
        headers=bearer(first_challenge),
        json={"recovery_code": recovery_codes[0]},
    )
    assert first.status_code == 200

    client.post(
        "/logout",
        headers=bearer(first.get_json()["access_token"]),
    )

    second_challenge = begin_mfa_login(client)
    reused = client.post(
        "/mfa/verify-login",
        headers=bearer(second_challenge),
        json={"recovery_code": recovery_codes[0]},
    )
    assert reused.status_code == 401
    assert reused.get_json()["code"] == "mfa_failed"


def test_mfa_challenge_locks_after_maximum_bad_attempts(client, user):
    access = login(client).get_json()["access_token"]
    _, recovery_codes = enable_mfa(client, access)

    challenge = begin_mfa_login(client)
    for _ in range(5):
        failure = client.post(
            "/mfa/verify-login",
            headers=bearer(challenge),
            json={"code": "000000"},
        )
        assert failure.status_code == 401

    blocked = client.post(
        "/mfa/verify-login",
        headers=bearer(challenge),
        json={"recovery_code": recovery_codes[0]},
    )
    assert blocked.status_code == 401
    assert blocked.get_json()["code"] == "invalid_mfa_challenge"


def test_mfa_can_be_disabled_only_with_password_and_second_factor(client, user):
    access = login(client).get_json()["access_token"]
    _, recovery_codes = enable_mfa(client, access)

    challenge = begin_mfa_login(client)
    completed = client.post(
        "/mfa/verify-login",
        headers=bearer(challenge),
        json={"recovery_code": recovery_codes[0]},
    )
    fresh_access = completed.get_json()["access_token"]

    wrong = client.post(
        "/mfa/disable",
        headers=bearer(fresh_access),
        json={
            "current_password": "wrong",
            "recovery_code": recovery_codes[1],
        },
    )
    assert wrong.status_code == 401

    disabled = client.post(
        "/mfa/disable",
        headers=bearer(fresh_access),
        json={
            "current_password": PASSWORD,
            "recovery_code": recovery_codes[1],
        },
    )
    assert disabled.status_code == 200
    assert client.get("/profile", headers=bearer(fresh_access)).status_code == 401

    direct_login = login(client)
    assert direct_login.status_code == 200
    assert direct_login.get_json()["access_token"]
