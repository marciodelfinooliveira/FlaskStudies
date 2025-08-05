import os

class DevConfig:
    def __init__(self):
        self.ENV = os.environ.get('STATE', 'development')
        self.DEBUG = os.environ.get('DEBUG', 'True') == 'True'
        self.PORT = os.environ.get('PORT', '5000')
        self.HOST = os.environ.get('HOST', '0.0.0.0')
        self.SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI_DEV')
        self.SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS', 'False') == 'True'
        self.JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')