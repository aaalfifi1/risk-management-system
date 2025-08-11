# =====================================================
# == المحتوى الكامل والمُصحح لملف src/__init__.py ==
# =====================================================
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app = Flask(__name__, template_folder='../templates')
    
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'your_secret_key'

    db.init_app(app)

    # هذا هو الاستيراد الصحيح الآن
    from .routes import main_bp
    app.register_blueprint(main_bp)

    return app

