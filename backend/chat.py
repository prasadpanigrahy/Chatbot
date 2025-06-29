# 📁 chat.py

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import db, Message
import openai
import os

openai.api_key = os.getenv("OPENAI_API_KEY")

chat = Blueprint('chat', __name__)

@chat.route('/chat', methods=['POST'])
@login_required
def chat_with_bot():
    user_input = request.json['message']
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": user_input}]
    )
    reply = response['choices'][0]['message']['content']
    msg = Message(user_id=current_user.id, text=user_input, response=reply)
    db.session.add(msg)
    db.session.commit()
    return jsonify({'reply': reply})
