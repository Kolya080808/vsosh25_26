#!/usr/bin/env python3
"""
Дополнительные уязвимости для тестирования сканера
"""

import os
import subprocess
import pickle
import hashlib
import random
import sqlite3
from flask import request

# Уязвимость: Hardcoded Password (правило 1)
DB_PASSWORD = "MyDatabasePassword123!"
ROOT_PASS = "toor"
SECRET_KEY = "django-insecure-abcdefghijklmnopqrstuvwxyz123456"

# Уязвимость: Hardcoded API Token (правило 3)
STRIPE_API_KEY = "sk_live_abcdefghijklmnopqrstuvwxyz123456"
TWILIO_AUTH_TOKEN = "abc123def456ghi789jkl012mno345"
SLACK_TOKEN = "xoxb-1234567890-abcdefghijklmnopqrstuvwx"

# Уязвимость: JWT Secret Hardcoded (правило 4)
JWT_ALGORITHM = "HS256"
JWT_SECRET_KEY = "jwt-super-secret-key-2024-change-me-please"

# Уязвимость: Command Injection via User Input (правило 7)
def process_user_input_vulnerable():
    user_input = request.args.get('cmd', '')
    # Прямое использование os.system с пользовательским вводом
    os.system(user_input)

def eval_user_input_vulnerable():
    user_input = request.form.get('code', '')
    # Прямое использование eval с пользовательским вводом
    eval(user_input)

def exec_user_input_vulnerable():
    user_input = request.json.get('script', '')
    # Прямое использование exec с пользовательским вводом
    exec(user_input)

# Уязвимость: SQL Injection с разными вариантами (правило 5)
def sql_injection_variants():
    # Вариант 1: Конкатенация строк
    user_id = request.args.get('id', '1')
    query1 = "SELECT * FROM users WHERE id = " + user_id
    
    # Вариант 2: Форматирование строк
    username = request.args.get('username', 'admin')
    query2 = "SELECT * FROM users WHERE username = '%s'" % username
    
    # Вариант 3: f-strings (тоже уязвимо!)
    email = request.args.get('email', 'test@example.com')
    query3 = f"SELECT * FROM users WHERE email = '{email}'"
    
    # Вариант 4: INSERT инъекция
    name = request.args.get('name', 'test')
    query4 = "INSERT INTO logs (action) VALUES ('" + name + "')"
    
    conn = sqlite3.connect('test.db')
    conn.execute(query1)
    conn.execute(query2)
    conn.execute(query3)
    conn.execute(query4)
    conn.close()

# Уязвимость: Subprocess with Shell (правило 10)
def subprocess_vulnerabilities():
    # subprocess.run с shell=True
    cmd1 = request.args.get('cmd1', 'echo test')
    subprocess.run(cmd1, shell=True)
    
    # subprocess.Popen с shell=True
    cmd2 = request.args.get('cmd2', 'ls -la')
    process = subprocess.Popen(cmd2, shell=True)
    process.wait()
    
    # subprocess.call с shell=True
    cmd3 = request.args.get('cmd3', 'pwd')
    subprocess.call(cmd3, shell=True)
    
    # subprocess.getoutput (использует shell)
    cmd4 = request.args.get('cmd4', 'whoami')
    output = subprocess.getoutput(cmd4)
    print(output)

# Уязвимость: Weak Cryptographic Hash (правило 11)
def weak_hashes():
    password = request.form.get('password', '')
    
    # MD5
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    
    # SHA1
    sha1_hash = hashlib.sha1(password.encode()).hexdigest()
    
    # Еще MD5
    hash_obj = hashlib.md5()
    hash_obj.update(password.encode())
    md5_hash2 = hash_obj.hexdigest()
    
    return md5_hash, sha1_hash, md5_hash2

# Уязвимость: Insecure Random (правило 12)
def insecure_random_usage():
    # Генерация токена
    token = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(32))
    
    # Генерация пароля
    password = ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') for _ in range(16))
    
    # Генерация ID
    user_id = random.randint(100000, 999999)
    
    # Случайный выбор
    random_choice = random.choice(['admin', 'user', 'guest'])
    
    return token, password, user_id, random_choice

# Уязвимость: SSL Certificate Verification Disabled (правило 6)
def insecure_requests():
    import requests
    
    # Полное отключение проверки
    response1 = requests.get('https://example.com', verify=False)
    
    # Отключение через сессию
    session = requests.Session()
    session.verify = False
    response2 = session.get('https://api.example.com')
    
    return response1.text, response2.text

# Уязвимость: Insecure Deserialization (правило 9)
def insecure_deserialization():
    data = request.get_data()
    
    # pickle.loads
    try:
        obj = pickle.loads(data)
    except:
        obj = None
    
    # pickle.load с файлом
    filename = request.args.get('file', 'data.pickle')
    with open(filename, 'rb') as f:
        obj2 = pickle.load(f)
    
    return obj, obj2

# Уязвимость: os.system (правило 2)
def os_system_vulnerable():
    cmd = request.args.get('command', '')
    os.system(cmd)

# Уязвимость: os.popen (аналогично rule 7)
def os_popen_vulnerable():
    cmd = request.args.get('cmd', '')
    output = os.popen(cmd).read()
    return output

if __name__ == '__main__':
    print("Тестирование уязвимостей...")
    print("MD5 хэш:", hashlib.md5(b"test").hexdigest())
    print("SHA1 хэш:", hashlib.sha1(b"test").hexdigest())
    print("Случайное число:", random.randint(1, 100))
    print("Случайный диапазон:", random.randrange(100, 1000))
