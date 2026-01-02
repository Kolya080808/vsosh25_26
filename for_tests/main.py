# Уязвимость: Жестко заданный пароль
password = "supersecret"

# Уязвимость: жёстко заданный API ключ
api_key = "AKIA1234567890ABCDEFGH"

# Уязвимость: использование устаревшей (уязвимой) версии библиотеки (requirements.txt)
# (эту строку нужно записать в файл requirements.txt отдельно):
# flask==1.1.2

# Уязвимость: SQL Injection
import sqlite3
def get_user(uid):
    query = "SELECT * FROM users WHERE id=" + uid
    sqlite3.connect("db.sqlite").execute(query)

# Уязвимость: Command Injection
import os
user_input = "rm -rf /"
os.system(user_input)

# Уязвимость: Hardcoded JWT secret
jwt_secret = "myjwtsecret"

# Уязвимость: SSL Verification Disabled
import requests
requests.get('https://evilsite.com', verify=False)

# Уязвимость: Dangerous eval
user_code = "print('hello')"
eval(user_code)

# Уязвимость: Insecure deserialization
import pickle
data = b"..."  # untrusted data
pickle.loads(data)

# Уязвимость: Weak hash
import hashlib
hashlib.md5(b"test").hexdigest()

# Уязвимость: Insecure random
import random
random.randint(1, 10)

# Дополнительные уязвимости для полного покрытия правил:

# Уязвимость: Subprocess with Shell (правило 10)
import subprocess
def run_command(cmd):
    subprocess.run(cmd, shell=True)  # shell=True - уязвимость!

# Уязвимость: SQL Injection с INSERT (дополнение для правила 5)
def add_user(name, email):
    query = "INSERT INTO users (name, email) VALUES ('" + name + "', '" + email + "')"
    sqlite3.connect("db.sqlite").execute(query)

# Уязвимость: SQL Injection с UPDATE (дополнение для правила 5)
def update_user(id, name):
    query = "UPDATE users SET name='" + name + "' WHERE id=" + id
    sqlite3.connect("db.sqlite").execute(query)

# Уязвимость: SQL Injection с DELETE (дополнение для правила 5)
def delete_user(id):
    query = "DELETE FROM users WHERE id=" + id
    sqlite3.connect("db.sqlite").execute(query)

# Уязвимость: SHA1 weak hash (дополнение для правила 11)
hashlib.sha1(b"test").hexdigest()

# Уязвимость: random.randrange (дополнение для правила 12)
random.randrange(1, 100)

