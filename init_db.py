# --- الكود الكامل لملف init_db.py (النسخة المستقرة) ---
import os
from run import app, db, User

# بيانات المستخدمين الافتراضيين
# ملاحظة: تم حذف البريد الإلكتروني من هنا
users_to_create = {
    'admin': 'Admin@2025',
    'testuser': 'Test@1234',
    'reporter': 'Reporter@123'
}

def initialize_database():
    print("Starting database initialization...")
    with app.app_context():
        # حذف الجداول القديمة (إذا كانت موجودة
