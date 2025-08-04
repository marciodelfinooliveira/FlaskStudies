FROM python:3.9.23-alpine3.21

LABEL maintainer="marciodelinooliveira@gmail.com"
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN apk add --no-cache postgresql-dev build-base

WORKDIR /app
COPY src/ /app/src
COPY requirements.txt /app/
COPY dotenv_files/ /dotenv_files/
COPY run.py /app/

RUN python -m venv /venv && \
    /venv/bin/pip install --upgrade pip && \
    /venv/bin/pip install -r /app/requirements.txt && \
    chmod +x /commands.sh

ENV PATH="/venv/bin:/dotenv_files:$PATH"

EXPOSE 5000

CMD ["commands.sh"]