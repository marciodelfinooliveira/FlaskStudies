from flask import Blueprint, jsonify
from src.controllers.user_controller import users

api = Blueprint('api', __name__)

@api.route('/')
def home():
    return jsonify({"message": "API Flask está funcionando!"}), 200

api.register_blueprint(users, url_prefix='/users')