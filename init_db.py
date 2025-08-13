# --- الكود الكامل لملف init_db.py (نسخة البريد الإلكتروني المصححة) ---
import os
from run import app, db, User

# بيانات المستخدمين الافتراضيين مع البريد الإلكتروني
users_to_create = {
    'admin': ('Admin@2025', 'twag1212@gmail.com'),
    'testuser': ('Test@1234', 'testuser@example.com'),
    'reporter': ('Reporter@123', 'reporter@example.com')
}

def initialize_database():
    print("Starting database initialization...")
    with app.app_context():
        # حذف الجداول القديمة (إذا كانت موجودة) وإعادة إنشائها
        # هذا يضمن أن الهيكل الجديد مع عمود 'email' يتم تطبيقه
        db.drop_all()
        db.create_all()
        print("Tables dropped and recreated successfully.")

        # إنشاء المستخدمين الافتراضيين
        for username, (password, email) in users_to_create.items():
            user = User.query.filter_by(username=username).first()
            if not user:
                new_user = User(username=username, email=email)
                new_user.set_password(password)
                db.session.add(new_user)
                print(f"User '{username}' created.")
            else:
                print(f"User '{username}' already exists.")
        
        db.session.commit()
        print("Database initialization complete.")

# هذا الجزء يسمح بتشغيل الملف مباشرة من سطر الأوامر
if __name__ == '__main__':
    initialize_database()
