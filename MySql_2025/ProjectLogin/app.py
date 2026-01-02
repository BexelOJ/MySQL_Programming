# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, redirect, session
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

from flask import jsonify

app = Flask(__name__)
app.secret_key = 'Exin@1234'  # Replace with a strong secret key

# MySQL connection config
db_config = {
    'user': 'exin',
    'password': 'Exin@1234',
    'host': '192.168.0.102',
    'database': 'garudabase',
    'port': 3306,
    'auth_plugin': 'mysql_native_password'
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')

        if not username or not password:
            if request.is_json:
                return jsonify({"error": "Please fill out all fields."}), 400
            else:
                return render_template('register.html', error='Please fill out all fields.')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username=%s', (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()
            conn.close()
            if request.is_json:
                return jsonify({"error": "Username already taken."}), 409
            else:
                return render_template('register.html', error='Username already taken.')

        hashed_password = generate_password_hash(password)
        cursor.execute('INSERT INTO users (username, password) VALUES (%s, %s)', (username, hashed_password))
        conn.commit()
        cursor.close()
        conn.close()

        if request.is_json:
            return jsonify({"message": "User registered successfully."}), 201
        else:
            return redirect('/login')

    # For GET request (usually from browser)
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE username=%s', (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            if request.is_json:
                return jsonify({"message": "Login successful."}), 200
            else:
                return redirect('/additional_info')
        else:
            if request.is_json:
                return jsonify({"error": "Invalid username or password."}), 401
            else:
                return render_template('login.html', error='Invalid username or password')

    # GET request (browser)
    return render_template('login.html')


@app.route('/additional_info', methods=['GET', 'POST'])
def additional_info():
    if 'user_id' not in session:
        if request.is_json:
            return jsonify({"error": "Unauthorized"}), 401
        else:
            return redirect('/login')

    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            address = data.get('address')
            phone = data.get('phone')
        else:
            address = request.form.get('address')
            phone = request.form.get('phone')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET address=%s, phone=%s WHERE id=%s',
                       (address, phone, session['user_id']))
        conn.commit()
        cursor.close()
        conn.close()

        if request.is_json:
            return jsonify({"message": "Information updated successfully!"}), 200
        else:
            return render_template('additional_info.html', message='Information updated successfully!')

    # For GET request, if from Android app, send user info JSON (optional)
    if request.is_json:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT address, phone FROM users WHERE id=%s', (session['user_id'],))
        user_info = cursor.fetchone()
        cursor.close()
        conn.close()
        return jsonify(user_info or {}), 200
    else:
        return render_template('additional_info.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect('/login')

#if __name__ == '__main__':
#    app.run(host='0.0.0.0', port=5051)

@app.errorhandler(404)
def page_not_found(e):
    app.logger.error(f'404 Not Found: {request.url}')
    return "Page not found", 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5051, debug=True)


