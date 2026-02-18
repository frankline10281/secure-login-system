from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from database import db, User
import re
import hashlib
import requests
from zxcvbn import zxcvbn
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Password checking functions (from your previous project)
def check_pwned(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
        hashes = [line.split(':')[0] for line in response.text.splitlines()]
        return suffix in hashes
    except:
        return False

def check_password_strength(password):
    score = 0
    feedback = []
    
    # Length check
    if len(password) >= 12:
        score += 25
        feedback.append("✅ Good length")
    elif len(password) >= 8:
        score += 15
        feedback.append("⚠️ Decent length")
    else:
        score += 5
        feedback.append("❌ Too short")
    
    # Character checks
    if re.search(r'[A-Z]', password):
        score += 15
        feedback.append("✅ Has uppercase")
    else:
        feedback.append("❌ No uppercase")
    
    if re.search(r'[a-z]', password):
        score += 15
        feedback.append("✅ Has lowercase")
    else:
        feedback.append("❌ No lowercase")
    
    if re.search(r'[0-9]', password):
        score += 15
        feedback.append("✅ Has numbers")
    else:
        feedback.append("❌ No numbers")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 20
        feedback.append("✅ Has special chars")
    else:
        feedback.append("❌ No special chars")
    
    # zxcvbn analysis
    result = zxcvbn(password)
    if result['score'] >= 3:
        score += 10
        feedback.append("✅ Not easily guessable")
    else:
        feedback.append("⚠️ Common/guessable")
    
    # Check if pwned
    is_pwned = check_pwned(password)
    if is_pwned:
        return {
            'score': 0,
            'strength': 'LEAKED',
            'color': '#ff4444',
            'feedback': ['🚨 This password has been leaked!'],
            'pwned': True
        }
    
    # Determine strength
    if score >= 80:
        strength = "VERY STRONG"
        color = "#00C851"
    elif score >= 60:
        strength = "STRONG"
        color = "#33b5e5"
    elif score >= 40:
        strength = "MEDIUM"
        color = "#ffbb33"
    elif score >= 20:
        strength = "WEAK"
        color = "#FF8800"
    else:
        strength = "VERY WEAK"
        color = "#ff4444"
    
    return {
        'score': min(score, 100),
        'strength': strength,
        'color': color,
        'feedback': feedback[:5],
        'pwned': False
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
        
        # Check password strength
        strength_result = check_password_strength(password)
        
        if strength_result['pwned']:
            flash('This password has been leaked! Choose another.', 'danger')
            return redirect(url_for('register'))
        
        if strength_result['score'] < 40:
            flash('Password too weak! Please choose a stronger password.', 'warning')
            return redirect(url_for('register'))
        
        # Create user
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            password_score=strength_result['score'],
            password_feedback=str(strength_result['feedback'])
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/check-password', methods=['POST'])
def check_password():
    data = request.get_json()
    password = data.get('password', '')
    result = check_password_strength(password)
    return jsonify(result)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    print("🔐 Secure Login System Starting...")
    print("📱 Open http://localhost:5000")
    app.run(debug=True, port=5000)