from flask import (
    request, 
    Response, 
    json, 
    Blueprint, 
    jsonify,
    current_app
    )
from src import db
from src.models.user_model import User, BlacklistedToken
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps

users = Blueprint("users", __name__, url_prefix="/users")

def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        
        token = None
        auth_header = request.headers.get('Authorization', '')
        
        if auth_header.startswith('Bearer '):
            token = auth_header.split(" ")[1]
        else:
            return jsonify({
                'status': 'error',
                'message': 'Formato de token inválido. Use: Bearer <token>',
                'code': 401
            }), 401

        if not token:
            return jsonify({
                'status': 'error',
                'message': 'Token de autenticação ausente!',
                'code': 401
            }), 401

        if BlacklistedToken.query.filter_by(token=token).first():
            return jsonify({
                'status': 'error',
                'message': 'Token revogado. Faça login novamente.',
                'code': 401
            }), 401

        try:
            payload = jwt.decode(
                token, 
                current_app.config['JWT_SECRET_KEY'], 
                algorithms=["HS256"]
            )
            request.user_id = payload['user_id']
            
        except jwt.ExpiredSignatureError:
            return jsonify({
                'status': 'error',
                'message': 'Token expirado!',
                'code': 401
            }), 401
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': 'Token inválido!',
                'code': 401
            }), 401

        return f(*args, **kwargs)
    return decorated

@users.route('/add', methods = ["POST"])
def addUser():

    if request.is_json:
        data = request.get_json()
    else:
        data = request.form

    if not data or not all(key in data for key in ['username', 'email', 'password']):
        return jsonify({
            'status': 'error',
            'message': 'Dados ausentes. É necessário fornecer username, email e password.',
            'code': 400
        }), 400

    try:

        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        hashed_password = generate_password_hash(password)

        user = User(
            username = username,
            email = email,
            password = hashed_password
        )

        if User.query.filter_by(email=email).first():
            return jsonify({
            'status': 'error',
            'message': 'Este usuário já está cadastrado.',
            'code': 409
            }), 409

        db.session.add(user)

        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': 'Usuário adicionado com sucesso!',
            'code': 201,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            }
        }), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': 'Não foi possível salvar o usuário no banco de dados.',
            'code': 500
        }), 500
    

@users.route('/all', methods=['GET'])
@jwt_required
def get_all_users():
    """Retorna uma lista de todos os usuários."""

    users_list = User.query.all()
    return jsonify({
        'status': 'success',
        'code': 200,
        'users': [user.to_dict() for user in users_list]
    }), 200


@users.route('/<int:user_id>', methods=['GET'])
@jwt_required
def get_user(user_id):
    """Retorna um usuário específico pelo seu ID."""

    user = User.query.get(user_id)
    if not user:
        return jsonify({
            'status': 'error',
            'message': 'Usuário não encontrado.',
            'code': 404
        }), 404
    
    return jsonify({
        'status': 'success',
        'code': 200,
        'user': user.to_dict()
    }), 200


@users.route('/<int:user_id>', methods=['PUT', 'PATCH'])
@jwt_required
def update_user(user_id):
    """Atualiza os dados de um usuário."""

    refresh_token = request.headers['Authorization'].split(" ")[1]
    data = jwt.decode(refresh_token, current_app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
    user_jwt_id = data['user_id']

    if user_jwt_id != user_id:
        return jsonify({
            'status': 'error',
            'message': 'Token não válido para este usuário.',
            'code': 404
        }), 404

    user = User.query.get(user_id)

    if not user:
        return jsonify({
            'status': 'error',
            'message': 'Usuário não encontrado.',
            'code': 404
        }), 404

    if request.is_json:
        data = request.get_json()
    else:
        data = request.form

    user.username = data.get('username', user.username) if data.get('username') else user.username
    user.email = data.get('email', user.email) if data.get('email') else user.email

    try:
        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': 'Usuário atualizado com sucesso!',
            'code': 200,
            'user': user.to_dict()
        }), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': 'Não foi possível atualizar o usuário.',
            'code': 500
        }), 500


@users.route('/<int:user_id>', methods=['DELETE'])
@jwt_required
def delete_user(user_id):
    """Deleta um usuário."""

    refresh_token = request.headers['Authorization'].split(" ")[1]
    data = jwt.decode(refresh_token, current_app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
    user_jwt_id = data['user_id']

    if user_jwt_id != user_id:
        return jsonify({
            'status': 'error',
            'message': 'Token não válido para este usuário.',
            'code': 404
        }), 404

    user = User.query.get(user_id)

    if not user:
        return jsonify({
            'status': 'error',
            'message': 'Usuário não encontrado.',
            'code': 404
        }), 404

    if not user.is_active:
        return jsonify({
            'status': 'error',
            'message': 'Este usuário já está inativo.',
            'code': 400
        }), 400

    try:
        user.is_active = False
        user.deleted_at = datetime.utcnow()

        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': 'Usuário deletado com sucesso!',
            'code': 200
        }), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': 'Não foi possível deletar o usuário.',
            'code': 500
        }), 500


@users.route('/signin', methods=["POST"])
def signin():
    """Realiza o login do usuário e retorna os tokens de acesso e atualização."""

    if request.is_json:
        data = request.get_json()
    else:
        data = request.form

    if not data or not all(key in data for key in ['email', 'password']):
        return jsonify({
            'status': 'error',
            'message': 'Dados ausentes. É necessário fornecer email e password.',
            'code': 400
        }), 400

    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({
            'status': 'error',
            'message': 'Credenciais inválidas.',
            'code': 401
        }), 401

    try:
        access_token = jwt.encode(
            {
                'user_id': user.id,
                'exp': datetime.utcnow() + timedelta(minutes=30)
            },
            current_app.config['JWT_SECRET_KEY'],
            algorithm="HS256"
        )
        access_token = access_token.decode('utf-8') if isinstance(access_token, bytes) else access_token

        refresh_token = jwt.encode(
            {
                'user_id': user.id,
                'exp': datetime.utcnow() + timedelta(hours=2)
            },
            current_app.config['JWT_SECRET_KEY'],
            algorithm="HS256"
        )
        refresh_token = refresh_token.decode('utf-8') if isinstance(refresh_token, bytes) else refresh_token

        return jsonify({
            'status': 'success',
            'message': 'Login realizado com sucesso!',
            'code': 200,
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Erro ao gerar tokens: {str(e)}',
            'code': 500
        }), 500


@users.route('/refresh', methods=['POST'])
@jwt_required
def refresh():
    """Gera um novo access_token a partir de um refresh_token válido."""

    refresh_token = request.headers['Authorization'].split(" ")[1]
    data = jwt.decode(refresh_token, current_app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
    user_id = data['user_id']

    new_access_token = jwt.encode(
        {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(minutes=30)
        },
        current_app.config['JWT_SECRET_KEY'],
        algorithm="HS256"
    )

    return jsonify({
        'status': 'success',
        'code': 200,
        'access_token': new_access_token
    }), 200


@users.route('/logout', methods=['POST'])
@jwt_required
def logout():
    """
    Desloga o usuário adicionando o token de acesso atual à blacklist.
    """
    
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(" ")[1]

    try:
        blacklisted_token = BlacklistedToken(token=token)
        db.session.add(blacklisted_token)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Logout realizado com sucesso.',
            'code': 200
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': 'Não foi possível processar a solicitação de logout.',
            'code': 500
        }), 500


@users.route('/validate', methods=["POST"])
def validate_token():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    try:
        decoded = jwt.decode(
            token,
            current_app.config['JWT_SECRET_KEY'],
            algorithms=["HS256"]
        )
        return jsonify({'valid': True, 'user_id': decoded['user_id']}), 200
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 401