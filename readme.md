# 🔐 Secure Flask Authentication API

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Flask](https://img.shields.io/badge/Flask-API-black)
![JWT](https://img.shields.io/badge/Auth-JWT-green)
![Security](https://img.shields.io/badge/Security-Hardened-red)

A production-style authentication API built using Flask that implements secure user authentication with JWT, refresh tokens, token blacklisting, and role-based access control.

---

## 🚀 Features

- User Registration & Login
- JWT Authentication (Access + Refresh Tokens)
- Token Refresh System
- Token Blacklisting (Secure Logout)
- Role-Based Access Control (Admin/User)
- Rate Limiting (Brute-force Protection)
- Input Validation & Error Handling
- Secure Password Hashing
- Request Logging

---

## 🧠 Security Features

- Short-lived access tokens
- Refresh token-based session management
- Token revocation using blacklist
- Protection against IDOR
- Brute-force protection
- Secrets managed using `.env`
- No hardcoded sensitive data

---

## 🛠️ Tech Stack

- Python (Flask)
- Flask-JWT-Extended
- Flask-SQLAlchemy
- Flask-Limiter
- SQLite

---

## 📦 Installation

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/secure-flask-auth-api.git
cd secure-flask-auth-api
```
### 2. Create Virtual Environment
```bash 
python -m venv venv
```
### 3. Activate Environment
#### Windows
```bash
venv\Scripts\activate
```
#### Linux / Mac
```bash
source venv/bin/activate
```
### 4. Install Dependencies
```bash
pip install -r requirements.txt
```
### 5. Install Dependencies
```bash
pip install -r requirements.txt
```
### 6. Setup Environment Variables
```bash
Create .env file:

SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret
```
### 6. Run Application
```bash
python app.py
```
Server runs at:

http://127.0.0.1:5000

### 🔑 Authentication Flow
```bash
Login → Access + Refresh Token
       ↓
Use Access Token → Access APIs
       ↓
Token Expired
       ↓
Use Refresh Token → New Access Token
       ↓
Logout → Tokens Revoked
```
## 📡 API Endpoints
### Authentication
```bash
Method	Endpoint	Description
POST	/register	Register user
POST	/login	    Login user
POST	/refresh	Get new access token
POST	/logout	    Logout user
```
### Protected
```bash
Method	Endpoint	  Description
GET	    /profile	  Get user profile
GET	    /users	      Admin only
GET	    /users/<id>	  Get user
PUT	    /users/<id>	  Update user
DELETE	/users/<id>	  Delete user
```

## 📁 Project Structure
```bash
├── app.py
├── config.py
├── models.py
├── requirements.txt
├── .env.example
├── .gitignore
└── users.db
```
## ⚠️ Important Notes
- .env is not included for security
- Use .env.example as reference
- SQLite is for development only
- Use PostgreSQL/MySQL in production

## 🧠 Future Improvements
- Refresh token rotation
- Token cleanup system
- Device/IP binding
- HTTPS deployment
- SIEM integration

## 👨‍💻 Author

Shadin K V

Cybersecurity Enthusiast

## ⭐ Connect with me
If you found this project inspiring, don’t forget to star the repo!

Let's connect on 🤝 [![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](www.linkedin.com/in/shadin-k-v-cybersecurity)

Medium ✍️ [![Medium](https://img.shields.io/badge/Medium-Read-black?style=flat&logo=medium)](https://medium.com/@shdnkval)
