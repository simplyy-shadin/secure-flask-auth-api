import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

    SQLALCHEMY_DATABASE_URI = "sqlite:///users.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=10)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)