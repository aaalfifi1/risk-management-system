# --- الكود الكامل والنهائي لملف init_db.py ---

import os
from run import app, db, User

# --- بيانات المستخدمين الافتراضيين ---
# هام: تأكد من أن بريد المدير (admin) هو بريد حقيقي لتستقبل عليه الإشعارات
users_to_create = {
    'admin': {'password': 'Admin@2025', 'email': 'twag1212@gmail.com'},
    'testuser': {'password': 'Test@1234', 'email': 'testuser@example.com'},
    'reporter': {'password': 'Reporter@123', 'email': 'reporter@example.com'}
}

with app.app_context():
    print("Starting database initialization...")
    
    # إنشاء جميع الجداول إذا لم تكن موجودة
    db.create_all()
    print("Tables created (if they didn't exist).")

    # إنشاء المستخدمين الافتراضيين
    for username, data in users_to_create.items():
        user = User.query.filter_by(username=username).first()
        if not user:
            new_user = User(username=username, email=data['email'])
            new_user.set_password(data['password'])
            db.session.add(new_user)
            print(f"User '{username}' created.")
        else:
            # تحديث البريد الإلكتروني إذا كان المستخدم موجوداً بالفعل
            if user.email != data['email']:
                user.email = data['email']
                print(f"User '{username}' email updated.")
            else:
                print(f"User '{username}' already exists.")

    # حفظ التغييرات في قاعدة البيانات
    db.session.commit()
    print("Database initialization complete.")
