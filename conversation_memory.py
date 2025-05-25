
from flask import session

def get_history():
    return session.get('chat_history', [])

def add_to_history(role, content):
    history = session.get('chat_history', [])
    history.append({"role": role, "content": content})
    session['chat_history'] = history

def clear_history():
    session['chat_history'] = []
