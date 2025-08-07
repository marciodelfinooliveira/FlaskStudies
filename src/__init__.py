import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from dotenv import load_dotenv
from src.config.config import Config
import redis
from kafka import KafkaProducer
import json

load_dotenv()

db = SQLAlchemy()
migrate = Migrate()
redis_client = redis.from_url(os.getenv('REDIS_URL'), decode_responses=True)

kafka_producer = KafkaProducer(
    bootstrap_servers='kafka:9092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

def create_app():
    app = Flask(__name__)
    
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("SQLALCHEMY_DATABASE_URI_DEV")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["DEBUG"] = True
    app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")
    
    db.init_app(app)
    
    from src.models.user_model import User
    
    migrate.init_app(app, db)
    
    from src.routes import api, users
    app.register_blueprint(api, url_prefix="/api")
    app.register_blueprint(users, url_prefix="/users")
    
    app.redis_client = redis_client

    app.config['KAFKA_TOPIC'] = 'user-lifecycle'
    app.config['KAFKA_BROKERS'] = 'kafka_broker:9092'
    app.config['KAFKA_GROUP_ID'] = 'email-service-group'
    
    app.config['SMTP_HOST'] = 'mailhog'
    app.config['SMTP_PORT'] = 1025
    app.config['SMTP_SENDER'] = 'noreply@flaskApiTest.com'

    app.kafka_producer = KafkaProducer(
        bootstrap_servers=app.config['KAFKA_BROKERS'],
        value_serializer=lambda v: json.dumps(v).encode('ascii'),
        key_serializer=lambda v: json.dumps(v).encode('ascii')
    )
    
    app.kafka_consumer = None
    
    return app