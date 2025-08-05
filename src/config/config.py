from src.config.dev_config import DevConfig
from src.config.production import ProdConfig

class Config:
    def __init__(self):
        self.dev_config = DevConfig()
        self.production = ProdConfig()
        
    def get_config(self):
        if self.dev_config.ENV == 'development':
            return self.dev_config
        return self.production