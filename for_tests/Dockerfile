# Уязвимый Dockerfile для тестирования
FROM ubuntu:18.04

# Уязвимость: использование root пользователя
USER root

# Уязвимость: установка уязвимых пакетов
RUN apt-get update && apt-get install -y \
    openssl=1.1.1-1ubuntu2.1~18.04.20 \
    python2.7 \
    python-pip \
    && rm -rf /var/lib/apt/lists/*

# Уязвимость: копирование секретов в образ
COPY .env /app/.env
COPY secrets.txt /app/secrets.txt

# Уязвимость: использование sudo в скриптах
RUN chmod +x /app/start.sh && \
    echo "sudo service apache2 start" >> /app/start.sh

# Уязвимость: открытие всех портов
EXPOSE 1-65535

# Уязвимость: запуск от root
CMD ["/app/start.sh"]
