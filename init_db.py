import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from datetime import datetime

# =============================================================================
# App Configuration
# =============================================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_that_should_be_changed')
# تأكد من أن هذا المتغير موجود في Render ويشير إلى قاعدة بيانات PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///risk_management.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# =============================================================================
# Database Models (Must match run.py AND include all dependencies)
# =============================================================================
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    users = db.relationship('User', backref='role', lazy=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)
    password_hash = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(150), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

# [إصلاح] إضافة نموذج AuditLog ليعرف db.drop_all() بالاعتمادية
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)
    # تعريف العلاقة (اختياري هنا ولكن جيد للممارسة)
    user = db.relationship('User', backref=db.backref('audit_logs', lazy=True))


# تعريف النماذج الأخرى لضمان عمل db.create_all() بشكل صحيح
class Risk(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    risk_code = db.Column(db.String(50), unique=True, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))

class StatusOption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

# =============================================================================
# Database Initialization Function
# =============================================================================
def initialize_database():
    with app.app_context():
        print("Starting database initialization...")
        
        # الآن يجب أن يعمل هذا الأمر بشكل صحيح لأنه يعرف كل الجداول
        db.drop_all()
        print("All tables dropped successfully.")
        db.create_all()
        print("All tables recreated successfully.")

        # --- إنشاء الأدوار ---
        roles_to_create = ['Admin', 'Pioneer', 'Reporter']
        for role_name in roles_to_create:
            if not Role.query.filter_by(name=role_name).first():
                db.session.add(Role(name=role_name))
        db.session.commit()
        print("Roles committed.")

        # --- إنشاء المستخدمين الافتراضيين ---
        users_to_create = [
            {'username': 'admin', 'full_name': 'مدير النظام', 'password': 'adminpass', 'role': 'Admin', 'email': 'admin@example.com'},
            {'username': 'pioneer', 'full_name': 'رائد المخاطر', 'password': 'pioneerpass', 'role': 'Pioneer', 'email': 'pioneer@example.com'},
            {'username': 'reporter', 'full_name': 'المبلغ', 'password': 'reporterpass', 'role': 'Reporter', 'email': 'reporter@example.com'}
        ]

        for user_data in users_to_create:
            if not User.query.filter_by(username=user_data['username']).first():
                role = Role.query.filter_by(name=user_data['role']).first()
                if role:
                    new_user = User(
                        username=user_data['username'],
                        full_name=user_data['full_name'],
                        email=user_data['email'],
                        role_id=role.id
                    )
                    new_user.set_password(user_data['password'])
                    db.session.add(new_user)
        db.session.commit()
        print("Default users committed.")

        # --- إنشاء خيارات الحالة ---
        if not StatusOption.query.first():
            status_options = ['جديد', 'تحت المراجعة', 'نشط', 'مُراقب', 'مُصعَّد', 'مغلق']
            for status_name in status_options:
                db.session.add(StatusOption(name=status_name))
            db.session.commit()
            print("Status options committed.")
        
        print("Database initialization complete.")

# =============================================================================
# Main Execution
# =============================================================================
if __name__ == '__main__':
    initialize_database()
