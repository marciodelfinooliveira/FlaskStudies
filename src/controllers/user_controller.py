from flask import (
    request, 
    json,
    Blueprint, 
    jsonify,
    current_app
    )
from src import db
from datetime import datetime, timedelta, timezone
from src.models.user_model import User
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import uuid
from functools import wraps
import smtplib
from email.message import EmailMessage
from kafka import KafkaConsumer
import time
from dotenv import load_dotenv
from threading import Thread
import logging
import os

if not os.path.exists('logs'):
    os.makedirs('logs')

logging.basicConfig(
    filename='logs/app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


load_dotenv()

users = Blueprint("users", __name__, url_prefix="/users")

def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization', '')
        
        if auth_header.startswith('Bearer '):
            token = auth_header.split(" ")[1]
        
        if not token:
            return jsonify({'status': 'error', 'message': 'Token de autenticação ausente!', 'code': 401}), 401

        try:
            payload = jwt.decode(
                token, 
                current_app.config['JWT_SECRET_KEY'], 
                algorithms=["HS256"]
            )
            jti = payload['jti']
            user_id = payload['user_id']
            
            is_blacklisted = current_app.redis_client.get(f"blacklist:jti:{jti}")
            if is_blacklisted:
                return jsonify({'status': 'error', 'message': 'Token revogado.', 'code': 401}), 401

            is_whitelisted = current_app.redis_client.get(f"whitelist:jti:{jti}")
            if not is_whitelisted or is_whitelisted != str(user_id):
                 return jsonify({'status': 'error', 'message': 'Token não reconhecido ou inválido.', 'code': 401}), 401
            
            request.user_id = user_id
            
        except jwt.ExpiredSignatureError:
            return jsonify({'status': 'error', 'message': 'Token expirado!', 'code': 401}), 401
        except (jwt.InvalidTokenError, KeyError):
            return jsonify({'status': 'error', 'message': 'Token inválido!', 'code': 401}), 401

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

        user_event = {
            'event_type': 'USER_REGISTERED',
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'timestamp_utc': datetime.now(timezone.utc).isoformat()
        }

        current_app.kafka_producer.send('user-lifecycle', value=user_event)
        current_app.kafka_producer.flush()

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
        access_token_expires_delta = timedelta(minutes=30)
        refresh_token_expires_delta = timedelta(hours=2)
        access_jti = str(uuid.uuid4())
        
        access_token_payload = {
            'user_id': user.id,
            'exp': datetime.now(timezone.utc) + access_token_expires_delta,
            'iat': datetime.now(timezone.utc),
            'jti': access_jti,
            'type': 'access'
        }

        access_token = jwt.encode(
            access_token_payload,
            current_app.config['JWT_SECRET_KEY'],
            algorithm="HS256"
        )
        
        current_app.redis_client.setex(
            f"whitelist:jti:{access_jti}", 
            int(access_token_expires_delta.total_seconds()), 
            user.id
        )

        refresh_token = jwt.encode(
            {
                'user_id': user.id,
                'exp': datetime.now(timezone.utc) + refresh_token_expires_delta,
                'iat': datetime.now(timezone.utc),
                'type': 'refresh'
            },
            current_app.config['JWT_SECRET_KEY'],
            algorithm="HS256"
        )

        return jsonify({
            'status': 'success',
            'message': 'Login realizado com sucesso!',
            'code': 200,
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 200
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Erro ao gerar tokens: {str(e)}'}), 500


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
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(" ")[1]

    try:
        payload = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        jti = payload['jti']
        exp_timestamp = payload['exp']
        remaining_time = exp_timestamp - datetime.now(timezone.utc).timestamp()
        
        if remaining_time > 0:
            current_app.redis_client.setex(f"blacklist:jti:{jti}", int(remaining_time), "revoked")
        
        current_app.redis_client.delete(f"whitelist:jti:{jti}")
        
        return jsonify({'status': 'success', 'message': 'Logout realizado com sucesso.', 'code': 200}), 200
    except (jwt.InvalidTokenError, KeyError) as e:
        return jsonify({'status': 'error', 'message': 'Token inválido ou malformado.'}), 401
    except Exception as e:
        return jsonify({'status': 'error', 'message': 'Não foi possível processar o logout.'}), 500


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
    

def start_kafka_consumer(app):
    """Inicia o consumidor Kafka em uma thread separada"""

    def run_consumer():
        with app.app_context():
            while True:
                try:
                    consumer = app.kafka_consumer
                    app.logger.info(f"Aguardando eventos do tópico '{app.config['KAFKA_TOPIC']}'...")
                    
                    for message in consumer:
                        event = message.value
                        app.logger.info(f"Evento recebido: {event}")
                        if event.get('event_type') == 'USER_REGISTERED':
                            send_welcome_email(event)
                
                except Exception as e:
                    app.logger.error(f"Erro no consumidor Kafka: {str(e)}", exc_info=True)
                    time.sleep(3)

    thread = Thread(target=run_consumer)
    thread.daemon = True
    thread.start()


def send_welcome_email(user_data, app=None):
    """Função para construir e enviar o e-mail de boas-vindas."""
    
    if app is None:
        app = current_app
        
    try:
        recipient_email = user_data.get('email')
        username = user_data.get('username')

        if not all([recipient_email, username]):
            app.logger.error("Dados insuficientes no evento para enviar e-mail.")
            return

        app.logger.info(f"Preparando e-mail para {recipient_email}...")
        
        msg = EmailMessage()
        msg['Subject'] = f"Bem-vindo(a) à nossa plataforma, {username}!"
        msg['From'] = app.config['SMTP_SENDER']
        msg['To'] = recipient_email
        msg.set_content(
            f"Olá {username},\n\nSeu cadastro foi realizado com sucesso!\n\n"
            "Estamos muito felizes em ter você conosco.\n\n"
            "Atenciosamente,\nA Equipe do Projeto."
        )

        app.logger.info(f"Conectando ao SMTP {app.config['SMTP_HOST']}:{app.config['SMTP_PORT']}...")
        
        with smtplib.SMTP(app.config['SMTP_HOST'], app.config['SMTP_PORT']) as s:
            app.logger.info("Conexão SMTP estabelecida, enviando e-mail...")
            s.send_message(msg)
            app.logger.info(f"E-mail enviado com sucesso para {recipient_email}")

    except Exception as e:
        app.logger.error(f"Falha ao enviar e-mail: {str(e)}", exc_info=True)
        

@users.route('/start-email-consumer', methods=['POST'])
def start_email_consumer():

    try:
        if not hasattr(current_app, 'kafka_consumer') or current_app.kafka_consumer is None:
            current_app.kafka_consumer = KafkaConsumer(
                current_app.config['KAFKA_TOPIC'],
                group_id=current_app.config['KAFKA_GROUP_ID'],
                bootstrap_servers=current_app.config['KAFKA_BROKERS'],
                value_deserializer=lambda v: json.loads(v.decode('utf-8')),
                auto_offset_reset='earliest',
                enable_auto_commit=True,
                session_timeout_ms=6000,
                heartbeat_interval_ms=2000
            )
            
            start_kafka_consumer(current_app._get_current_object())  # Passa a aplicação Flask
            
            return jsonify({
                'status': 'success',
                'message': 'Consumidor de e-mails iniciado com sucesso!',
                'code': 200
            }), 200
        else:
            return jsonify({
                'status': 'info',
                'message': 'Consumidor de e-mails já está em execução.',
                'code': 200
            }), 200
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Não foi possível iniciar o consumidor de e-mails: {str(e)}',
            'code': 500
        }), 500

