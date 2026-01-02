#!/bin/bash
# Скрипт с уязвимостями для тестирования

# Уязвимость: хардкод пароля в скрипте
DB_PASSWORD="SuperSecretDBPassword123!"
API_KEY="AKIAIOSFODNN7EXAMPLE12345"

# Уязвимость: использование sudo без пароля
sudo apt-get update
sudo apt-get install -y vulnerable-package

# Уязвимость: выполнение произвольной команды
USER_INPUT=$1
eval "$USER_INPUT"

# Уязвимость: чтение произвольного файла
FILE_TO_READ=$2
cat "$FILE_TO_READ"

# Уязвимость: запись в системные файлы
echo "malicious content" > /tmp/$3

# Уязвимость: запуск сервисов от root
service mysql start
service apache2 start

# Уязвимость: открытие портов
iptables -A INPUT -p tcp --dport 1:65535 -j ACCEPT

# Уязвимость: установка уязвимых версий пакетов
pip install flask==1.0.0
pip install django==1.11.0
pip install requests==2.0.0
