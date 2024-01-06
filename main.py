from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = 'your_secret_key'


# Function to create connection to SQLite database
def create_connection():
    conn = sqlite3.connect('users.db')
    return conn


# Function to create table if not exists
def create_table():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        );
    ''')
    conn.commit()
    conn.close()


# Register route - GET for displaying the registration form, POST for processing form data
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hash the password before storing it
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()

        return redirect(url_for('login'))
    return render_template('register.html')


# Login route - GET for displaying the login form, POST for processing form data
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, password FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            user_id, user_name, stored_password = user
            # Validate the password
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            if hashed_password == stored_password:
                session['user_id'] = user_id
                session['username'] = user_name
                return redirect(url_for('profile'))

        return render_template('login.html', error='Invalid username or password')

    return render_template('login.html')


# Profile route - Display the user's profile after successful login
@app.route('/profile')
def profile():
    if 'user_id' in session:
        return f"<h1>Welcome, {session['username']}!</h1>"
    return redirect(url_for('login'))


# Logout route - Clear session data and redirect to login page
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    create_table()
    app.run(debug=True)
