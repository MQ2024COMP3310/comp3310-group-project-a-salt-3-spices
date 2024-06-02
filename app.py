from flask import Flask
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

def create_app():
    app = Flask(__name__)

    # Set the secret key from the .env file
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

    # Initialize extensions and blueprints
    from . import db, main
    db.init_app(app)
    app.register_blueprint(main.main)

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
