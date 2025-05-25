from flask import Flask, render_template, request, redirect, url_for, session, g
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from clarifier import clarify_if_needed
import joblib
import pandas as pd


app = Flask(__name__)
app.secret_key = "your-secret-key"

DATABASE = "chatapp.db"

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    print("Init DB Worked")
    with app.app_context():
        db = get_db()
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS chat_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_session_id INTEGER NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(chat_session_id) REFERENCES chat_sessions(id)
        );
        ''')
        db.commit()

init_db()

# Helpers
def query_user(username):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return user

def get_user_by_id(user_id):
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

def save_message(chat_session_id, role, content):
    db = get_db()
    db.execute(
        "INSERT INTO chat_history (chat_session_id, role, content) VALUES (?, ?, ?)",
        (chat_session_id, role, content)
    )
    db.commit()

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_latest_session_id(user_id):
    db = get_db()
    result = db.execute("SELECT id FROM chat_sessions WHERE user_id = ? ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
    return result['id'] if result else None

def create_new_chat_session(user_id):
    db = get_db()
    db.execute("INSERT INTO chat_sessions (user_id) VALUES (?)", (user_id,))
    db.commit()
    return get_latest_session_id(user_id)

# Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        if not username or not password:
            return render_template('register.html', error="Username and password required.")
        if query_user(username):
            return render_template('register.html', error="Username already exists.")
        
        password_hash = generate_password_hash(password)
        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
            db.commit()
        except Exception as e:
            print("Error during registration:", e)
            return render_template('register.html', error="Registration failed: " + str(e))
        
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = query_user(username)
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))
        return render_template('login.html', error="Invalid username or password.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def chat():
    user = get_user_by_id(session['user_id'])
    if user is None:
        session.clear()
        return redirect(url_for('login'))
    db = get_db()

    # Get or create current chat session
    if 'current_chat_session_id' not in session:
        session['current_chat_session_id'] = create_new_chat_session(user['id'])

    current_session_id = session['current_chat_session_id']

    history = db.execute(
        "SELECT role, content, timestamp FROM chat_history WHERE chat_session_id = ? ORDER BY id ASC",
        (current_session_id,)
    ).fetchall()

    if request.method == 'POST':
        question = request.form['question'].strip()
        if question:
            save_message(current_session_id, 'user', question)

            # Prepare history and get bot reply
            chat_history_list = [{'role': row['role'], 'content': row['content']} for row in history[-10:]]
            chat_history_list.append({'role': 'user', 'content': question})

            bot_reply = clarify_if_needed(question, chat_history_list)
            save_message(current_session_id, 'bot', bot_reply)

            # Refresh history
            history = db.execute(
                "SELECT role, content, timestamp FROM chat_history WHERE chat_session_id = ? ORDER BY id ASC",
                (current_session_id,)
            ).fetchall()

    return render_template('index.html', history=history, username=user['username'])

@app.route('/new_chat', methods=['POST'])
@login_required
def new_chat():
    user = get_user_by_id(session['user_id'])
    session['current_chat_session_id'] = create_new_chat_session(user['id'])
    return redirect(url_for('chat'))

@app.route('/clear', methods=['POST'])
@login_required
def clear():
    user = get_user_by_id(session['user_id'])
    db = get_db()
    # Delete all chat history for all sessions of this user
    sessions = db.execute("SELECT id FROM chat_sessions WHERE user_id = ?", (user['id'],)).fetchall()
    for s in sessions:
        db.execute("DELETE FROM chat_history WHERE chat_session_id = ?", (s['id'],))
    db.commit()
    return redirect(url_for('chat'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_user_by_id(session['user_id'])
    db = get_db()
    sessions = db.execute(
        "SELECT id, created_at FROM chat_sessions WHERE user_id = ? ORDER BY created_at DESC",
        (user['id'],)
    ).fetchall()
    return render_template('dashboard.html', username=user['username'], sessions=sessions)
@app.route('/view_chat/<int:session_id>')
@login_required
def view_chat(session_id):
    user = get_user_by_id(session['user_id'])
    db = get_db()

    # Confirm session belongs to user
    session_owner = db.execute(
        "SELECT user_id FROM chat_sessions WHERE id = ?",
        (session_id,)
    ).fetchone()

    if not session_owner or session_owner['user_id'] != user['id']:
        return "Unauthorized", 403

    history = db.execute(
        "SELECT role, content, timestamp FROM chat_history WHERE chat_session_id = ? ORDER BY id ASC",
        (session_id,)
    ).fetchall()

    return render_template('view_chat.html', history=history, username=user['username'], session_id=session_id)
@app.route('/ask_cyber', methods=['GET', 'POST'])
def ask_cyber():
    result = None
    if request.method == 'POST':
        user_input = request.form['user_input']

        # Load model and dataset
        model = joblib.load("cybercrime_classifier_model.joblib")
        df = pd.read_csv("synthetic_cybercrime_dataset_indian_large.csv")
        df["cybercrime_type"] = df["cybercrime_type"].str.strip()

        # Predict
        predicted_category = model.predict([user_input])[0]
        law_info = df[df["cybercrime_type"] == predicted_category][["law_section", "law_description"]].drop_duplicates().iloc[0]

        result = {
            "input": user_input,
            "category": predicted_category,
            "section": law_info["law_section"],
            "description": law_info["law_description"]
        }

    return render_template("ask_cyber.html", result=result)

if __name__ == '__main__':
    app.run(debug=True)
