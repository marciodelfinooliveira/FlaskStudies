from src import create_app
from src.config.config import Config

app = create_app()
config = Config()

if __name__ == "__main__":
    app.run(
        host = config.dev_config.HOST,
        port = config.dev_config.PORT,
        debug = config.dev_config.DEBUG
    )
