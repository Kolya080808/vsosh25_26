#!/usr/bin/env python3
"""
Flask веб-приложение с уязвимостями для тестирования всех правил
"""

from flask import Flask, request, jsonify, render_template
import sqlite3
import pickle
import subprocess
import os
import requests
import hashlib
import random

app = Flask(__name__)

# Уязвимость: Hardcoded JWT secret (правило 4)
jwt_secret = "my_super_secret_jwt_key_2024_1234567890"

# Уязвимость: Hardcoded Password (правило 1)
database_password = "PostgresPass123!"
admin_password = "Admin@123456"

# Уязвимость: Hardcoded API Token (правило 3)
aws_access_key = "AKIAIOSFODNN7EXAMPLE"
aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
github_token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    # Уязвимость: SQL Injection (правило 5) с конкатенацией
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    conn = sqlite3.connect('users.db')
    # Классическая SQL инъекция
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    
    try:
        cursor = conn.execute(query)
        user = cursor.fetchone()
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    conn.close()
    
    if user:
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/search', methods=['GET'])
def search():
    # Уязвимость: SQL Injection с %s форматированием (правило 5)
    search_term = request.args.get('q', '')
    
    conn = sqlite3.connect('products.db')
    # SQL инъекция через %s
    query = "SELECT * FROM products WHERE name LIKE '%%%s%%'" % search_term
    
    try:
        cursor = conn.execute(query)
        results = cursor.fetchall()
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    conn.close()
    return jsonify({'results': results}), 200

@app.route('/execute', methods=['POST'])
def execute_command():
    # Уязвимость: Command Injection via User Input (правило 7)
    command = request.form.get('command', '')
    
    # Использование os.system с пользовательским вводом
    os.system(command)
    
    return jsonify({'message': 'Command executed'}), 200

@app.route('/eval', methods=['POST'])
def evaluate_code():
    # Уязвимость: Dangerous eval (правило 8)
    code = request.form.get('code', '')
    
    # Прямой eval с пользовательским вводом
    result = eval(code)
    
    return jsonify({'result': result}), 200

@app.route('/run', methods=['POST'])
def run_code():
    # Уязвимость: Command Injection via User Input (правило 7) с exec
    code = request.form.get('code', '')
    
    # Использование exec с пользовательским вводом
    exec(code)
    
    return jsonify({'message': 'Code executed'}), 200

@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    # Уязвимость: Insecure deserialization (правило 9)
    data = request.get_data()
    
    # Небезопасная десериализация pickle
    try:
        obj = pickle.loads(data)
        return jsonify({'message': 'Deserialized successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/process', methods=['POST'])
def process_data():
    # Уязвимость: Subprocess with Shell (правило 10)
    filename = request.form.get('filename', '')
    
    # subprocess.run с shell=True
    result = subprocess.run(f"process_file.sh {filename}", shell=True, capture_output=True, text=True)
    
    return jsonify({'output': result.stdout}), 200

@app.route('/call', methods=['POST'])
def call_process():
    # Уязвимость: Subprocess with Shell (правило 10) с subprocess.call
    command = request.form.get('command', '')
    
    # subprocess.call с shell=True
    return_code = subprocess.call(command, shell=True)
    
    return jsonify({'return_code': return_code}), 200

@app.route('/popen', methods=['POST'])
def popen_process():
    # Уязвимость: Subprocess with Shell (правило 10) с subprocess.Popen
    command = request.form.get('command', '')
    
    # subprocess.Popen с shell=True
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    
    return jsonify({'stdout': stdout.decode(), 'stderr': stderr.decode()}), 200

@app.route('/hash', methods=['POST'])
def hash_data():
    # Уязвимость: Weak Cryptographic Hash (правило 11)
    data = request.form.get('data', '')
    
    # Слабые хэш-функции
    md5_hash = hashlib.md5(data.encode()).hexdigest()
    sha1_hash = hashlib.sha1(data.encode()).hexdigest()
    
    return jsonify({
        'md5': md5_hash,
        'sha1': sha1_hash
    }), 200

@app.route('/random', methods=['GET'])
def get_random_number():
    # Уязвимость: Insecure Random (правило 12)
    # Генерация случайных чисел с помощью небезопасного генератора
    random_int = random.randint(1, 1000000)
    random_range = random.randrange(1000, 9999)
    
    return jsonify({
        'random_int': random_int,
        'random_range': random_range
    }), 200

@app.route('/request', methods=['GET'])
def make_request():
    # Уязвимость: SSL Certificate Verification Disabled (правило 6)
    url = request.args.get('url', 'https://example.com')
    
    # Отключение проверки SSL сертификата
    response = requests.get(url, verify=False)
    
    return jsonify({
        'status_code': response.status_code,
        'content': response.text[:100]
    }), 200

@app.route('/api', methods=['GET'])
def call_api():
    # Еще один пример отключения SSL проверки
    response = requests.get('https://api.example.com/data', verify=False, timeout=10)
    return response.json(), 200

@app.route('/update', methods=['POST'])
def update_user():
    # Уязвимость: SQL Injection с UPDATE (правило 5)
    user_id = request.form.get('id', '')
    new_email = request.form.get('email', '')
    
    conn = sqlite3.connect('users.db')
    # SQL инъекция в UPDATE
    query = "UPDATE users SET email = '" + new_email + "' WHERE id = " + user_id
    
    try:
        conn.execute(query)
        conn.commit()
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    conn.close()
    return jsonify({'message': 'User updated'}), 200

@app.route('/delete', methods=['POST'])
def delete_user():
    # Уязвимость: SQL Injection с DELETE (правило 5)
    user_id = request.form.get('id', '')
    
    conn = sqlite3.connect('users.db')
    # SQL инъекция в DELETE
    query = "DELETE FROM users WHERE id = " + user_id
    
    try:
        conn.execute(query)
        conn.commit()
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    conn.close()
    return jsonify({'message': 'User deleted'}), 200

if __name__ == '__main__':
    # Уязвимость: запуск в debug режиме
    app.run(debug=True, host='0.0.0.0', port=5000)
