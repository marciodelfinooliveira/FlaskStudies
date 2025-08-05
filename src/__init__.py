import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from dotenv import load_dotenv
from src.config.config import Config

load_dotenv()

db = SQLAlchemy()
migrate = Migrate()

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
    
    return app