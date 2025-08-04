#!/bin/sh

# O set -e garante que o script irá parar se algum comando falhar.
set -e

echo "Aguardando o banco de dados iniciar..."
while ! nc -z psql 5432; do
  sleep 1
done
echo "Banco de dados iniciado!"

flask db upgrade

exec flask run --host=0.0.0.0 --port=5000 --debugs