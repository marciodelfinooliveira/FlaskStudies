import os

class ProdConfig:

    def __init__(self):
        self.ENV = os.environ.get('STATE')
        self.DEBUG = os.environ.get('DEBUG')
        self.PORT = os.environ.get('PORT')
        self.HOST = os.environ.get('HOST')