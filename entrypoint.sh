#!/bin/sh

echo "Verificando configuração do banco de dados..."
echo "Database URI: ${SQLALCHEMY_DATABASE_URI_DEV}"

echo "Waiting for PostgreSQL to start..."
while ! nc -z db 5432; do sleep 1; done

echo "PostgreSQL started"

pip install flask-migrate

if [ ! -d "/app/migrations" ]; then
    echo "Inicializando sistema de migrations..."
    flask db init
fi

echo "Criando e aplicando migrations..."
flask db migrate -m "Automatic migration"
flask db upgrade

echo "Iniciando aplicação Flask em modo DEBUG..."
exec flask run --host=0.0.0.0 --port=5000 --debug