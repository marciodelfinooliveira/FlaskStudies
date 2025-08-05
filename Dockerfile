FROM python:3.7.9-alpine3.12

WORKDIR /app

RUN apk add --no-cache gcc musl-dev postgresql-dev netcat-openbsd

RUN mkdir -p /app/migrations

COPY . .

RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    chmod +x entrypoint.sh

CMD ["./entrypoint.sh"]