# المسار: config.py (يبقى كما هو تماماً)
import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-very-secret-key-that-is-hard-to-guess'
    
    # ▼▼▼ هذا هو السطر الأهم الذي سيتم استخدامه الآن ▼▼▼
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'risk_management.db')
        
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # إضافة مسارات الرفع هنا لتكون مركزية
    UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
    REPORTS_UPLOAD_FOLDER = os.path.join(basedir, 'reports_uploads')
