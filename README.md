# 🔐 Secure Login System with Password Strength Checker

A complete secure authentication system with real-time password strength checking and HaveIBeenPwned breach detection.

## ✨ Features
- ✅ User registration with real-time password strength checker
- ✅ HaveIBeenPwned API integration (checks 500M+ leaked passwords)
- ✅ Visual strength meter with color coding
- ✅ Password requirements checklist
- ✅ Secure password hashing with Werkzeug
- ✅ User session management with Flask-Login
- ✅ SQLite database for user storage
- ✅ Professional responsive CSS design
- ✅ Dashboard with user info and password strength display

## 🛠️ Tech Stack
- **Backend:** Python, Flask
- **Database:** SQLAlchemy, SQLite
- **Security:** Flask-Login, Werkzeug
- **Frontend:** HTML, CSS, JavaScript
- **APIs:** HaveIBeenPwned, zxcvbn

## 📦 Installation
```bash
# Clone the repository
git clone https://github.com/frankline10281/secure-login-system.git
cd secure-login-system

# Create virtual environment
python -m venv venv

# Activate it (Windows)
venv\Scripts\activate

# Install dependencies
pip install flask flask-sqlalchemy flask-login requests zxcvbn

# Run the app
python app.py