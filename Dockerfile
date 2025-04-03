# Базовый образ
FROM tiangolo/uwsgi-nginx-flask:python3.8-alpine

# Обновление пакетов
RUN apk update && apk upgrade

# Установка системных зависимостей
RUN apk add --no-cache \
    python3-dev \
    musl-dev \
    openssl-dev \
    libffi-dev \
    make \
    gcc \
    g++ \
    && pip3 install --upgrade pip

# Установка setuptools
RUN pip install setuptools

# Копирование requirements.txt и установка зависимостей
COPY requirements.txt /app/
RUN pip install -r /app/requirements.txt

# Копирование исходного кода приложения
COPY ./beecloack-api /app

# Настройка рабочей директории
WORKDIR /app

# Точка входа (используем wsgi.py)
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
