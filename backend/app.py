from flask import Flask, render_template, redirect, request, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import requests
import os

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "fallback_secret")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chatbot.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

# Set your OpenRouter API key
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    text = db.Column(db.Text)
    response = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Login manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@login_required
def index():
    messages = Message.query.filter_by(user_id=current_user.id).order_by(Message.timestamp).all()
    return render_template('index.html', messages=messages)

@app.route('/chat', methods=['POST'])
@login_required
def chat():
    user_message = request.json['message']
    try:
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "mistralai/mistral-7b-instruct",
                "messages": [
                    {"role": "system", "content": "You are RK, a helpful, friendly, and smart AI assistant."},
                    {"role": "user", "content": user_message}
                ]
            }
        )

        if response.status_code != 200:
            return jsonify({'reply': "⚠️ OpenRouter error. Please try again later."}), 500

        reply = response.json()['choices'][0]['message']['content']

    except Exception as e:
        reply = f"⚠️ Error: {str(e)}"

    new_msg = Message(user_id=current_user.id, text=user_message, response=reply)
    db.session.add(new_msg)
    db.session.commit()
    return jsonify({'reply': reply})

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        if User.query.filter_by(username=username).first():
            flash('⚠️ Username already exists. Please choose another.', 'warning')
            return redirect('/register')
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('✅ Registered successfully! Please login.', 'success')
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            flash('✅ Login successful!', 'success')
            return redirect('/')
        flash('❌ Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('✅ Logged out successfully.', 'info')
    return redirect('/login')

@app.route('/clear_chat', methods=['POST'])
@login_required
def clear_chat():
    try:
        Message.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# Start app
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
