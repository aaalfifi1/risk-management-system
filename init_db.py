import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta

# =============================================================================
# App Configuration (Must match run.py)
# =============================================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key_that_should_be_changed'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///risk_management.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# =============================================================================
# Database Models (Must match run.py exactly)
# =============================================================================
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    users = db.relationship('User', backref='role', lazy=True)

class User(db.Model):
    __tablename__ = 'user' # Explicitly set table name
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(150), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

class Risk(db.Model):
    # This model is defined here to ensure db.drop_all() and db.create_all() work correctly,
    # but we don't need to interact with it in this script.
    id = db.Column(db.Integer, primary_key=True)
    # Add other columns to match run.py if needed for full table creation
    risk_code = db.Column(db.String(50), unique=True, nullable=True)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300), nullable=False)

class StatusOption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

# =============================================================================
# Database Initialization Function
# =============================================================================
def initialize_database():
    with app.app_context():
        print("Starting database initialization with RBAC...")
        
        # Drop all tables and recreate them to ensure a clean state
        db.drop_all()
        db.create_all()
        print("Tables dropped and recreated successfully.")

        # --- Create Roles ---
        roles_to_create = ['Admin', 'Pioneer', 'Reporter']
        for role_name in roles_to_create:
            if not Role.query.filter_by(name=role_name).first():
                new_role = Role(name=role_name)
                db.session.add(new_role)
                print(f"Role '{role_name}' created.")
        db.session.commit()
        print("Roles committed to the database.")

        # --- Create Default Users ---
        # [إصلاح] استخدام full_name بدلاً من email وتعيين كلمة المرور
        users_to_create = [
            {'username': 'admin', 'full_name': 'مدير النظام', 'password': 'adminpass', 'role': 'Admin'},
            {'username': 'pioneer', 'full_name': 'رائد المخاطر', 'password': 'pioneerpass', 'role': 'Pioneer'},
            {'username': 'reporter', 'full_name': 'المبلغ', 'password': 'reporterpass', 'role': 'Reporter'}
        ]

        for user_data in users_to_create:
            if not User.query.filter_by(username=user_data['username']).first():
                role = Role.query.filter_by(name=user_data['role']).first()
                if role:
                    new_user = User(
                        username=user_data['username'],
                        full_name=user_data['full_name'], # [إصلاح]
                        role_id=role.id
                    )
                    new_user.set_password(user_data['password']) # [إصلاح]
                    db.session.add(new_user)
                    print(f"User '{user_data['username']}' created with role '{user_data['role']}'.")
        db.session.commit()
        print("Default users committed to the database.")

        # --- Create Status Options ---
        if not StatusOption.query.first():
            status_options = ['جديد', 'تحت المراجعة', 'نشط', 'مُراقب', 'مُصعَّد', 'مغلق']
            for status_name in status_options:
                db.session.add(StatusOption(name=status_name))
            print("Status options created.")
        db.session.commit()
        print("Status options committed to the database.")
        
        print("Database initialization complete.")

# =============================================================================
# Main Execution
# =============================================================================
if __name__ == '__main__':
    initialize_database()

