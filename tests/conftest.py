import pytest

from config import TestingConfig
from secure_api import create_app
from secure_api.extensions import db
from secure_api.models import User


@pytest.fixture()
def app():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def user(app):
    with app.app_context():
        user = User(
            username="alice",
            email="alice@example.com",
        )
        user.set_password("CorrectHorseBatteryStaple!42")
        db.session.add(user)
        db.session.commit()
        return user.id


@pytest.fixture()
def second_user(app):
    with app.app_context():
        user = User(
            username="bob",
            email="bob@example.com",
        )
        user.set_password("AnotherStrongPassphrase!42")
        db.session.add(user)
        db.session.commit()
        return user.id


@pytest.fixture()
def admin(app):
    with app.app_context():
        user = User(
            username="admin",
            email="admin@example.com",
            role="admin",
        )
        user.set_password("AdministrativePassphrase!42")
        db.session.add(user)
        db.session.commit()
        return user.id


def login(
    client,
    username="alice",
    password="CorrectHorseBatteryStaple!42",
):
    return client.post(
        "/login",
        json={
            "username": username,
            "password": password,
        },
    )
