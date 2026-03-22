from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,   
    jwt_required,
    get_jwt_identity,
    get_jwt                 
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import Config
from models import db, User
import re
import logging

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
jwt = JWTManager(app)

# ---------------- TOKEN BLACKLIST ----------------
blacklist = set()

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    return jwt_payload["jti"] in blacklist

# ---------------- RATE LIMIT ----------------
limiter = Limiter(get_remote_address, app=app)

# ---------------- LOGGING ----------------
logging.basicConfig(level=logging.INFO)

@app.before_request
def log_request():
    logging.info(f"{request.method} {request.path} from {request.remote_addr}")

# ---------------- HELPERS ----------------
def is_admin(user):
    return user.role == "admin"

def is_owner(user, user_id):
    return user.id == user_id

def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

# ---------------- HOME ----------------
@app.route("/")
def home():
    return {"message": "Flask API is running"}

# ---------------- REGISTER ----------------
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not username or not email or not password:
        return jsonify({"error": "All fields required"}), 400

    if not is_valid_email(email):
        return jsonify({"error": "Invalid email"}), 400

    if len(password) < 6:
        return jsonify({"error": "Password too weak"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 409

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists"}), 409

    user = User(username=username, email=email)
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

# ---------------- LOGIN ----------------
@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid input"}), 400

    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))

    return jsonify(
        access_token=access_token,
        refresh_token=refresh_token
    ), 200

# ---------------- PROFILE ----------------
@app.route("/profile", methods=["GET"])
@jwt_required()
def profile():
    user = User.query.get(int(get_jwt_identity()))

    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email
    }), 200

# ---------------- GET ALL USERS ----------------
@app.route("/users", methods=["GET"])
@jwt_required()
def get_users():
    current_user = User.query.get(int(get_jwt_identity()))

    if not is_admin(current_user):
        return jsonify({"error": "Admins only"}), 403

    users = User.query.all()

    return jsonify([
        {"id": u.id, "username": u.username, "email": u.email}
        for u in users
    ]), 200

# ---------------- GET USER ----------------
@app.route("/users/<int:user_id>", methods=["GET"])
@jwt_required()
def get_user(user_id):
    current_user = User.query.get(int(get_jwt_identity()))

    if not is_admin(current_user) and not is_owner(current_user, user_id):
        return jsonify({"error": "Unauthorized"}), 403

    user = User.query.get_or_404(user_id)

    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email
    }), 200

# ---------------- UPDATE USER ----------------
@app.route("/users/<int:user_id>", methods=["PUT"])
@jwt_required()
def update_user(user_id):
    current_user = User.query.get(int(get_jwt_identity()))
    user = User.query.get_or_404(user_id)
    data = request.get_json()

    if not is_admin(current_user) and not is_owner(current_user, user_id):
        return jsonify({"error": "Unauthorized"}), 403

    if "email" in data:
        if not is_valid_email(data["email"]):
            return jsonify({"error": "Invalid email"}), 400
        user.email = data["email"]

    db.session.commit()
    return jsonify({"message": "User updated successfully"}), 200

# ---------------- DELETE USER ----------------
@app.route("/users/<int:user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    current_user = User.query.get(int(get_jwt_identity()))
    user = User.query.get_or_404(user_id)

    if not is_admin(current_user):
        return jsonify({"error": "Admins only"}), 403

    db.session.delete(user)
    db.session.commit()

    return jsonify({"message": "User deleted successfully"}), 200

# ---------------- REFRESH TOKEN ----------------
@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    user_id = get_jwt_identity()

    new_access_token = create_access_token(identity=user_id)

    return jsonify(access_token=new_access_token), 200

# ------------------ LOGOUT ---------------------
@app.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    data = request.get_json()

    # Revoke current access token
    jti = get_jwt()["jti"]
    db.session.add(RevokedToken(jti=jti))

    # Revoke refresh token if provided
    refresh_token = data.get("refresh_token")
    if refresh_token:
        from flask_jwt_extended import decode_token
        decoded = decode_token(refresh_token)
        blacklist.add(decoded["jti"])

    return jsonify({"message": "Logged out from all sessions"}), 200

# ---------------- ERROR HANDLER ----------------
@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500

# ---------------- RUN ----------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=False)