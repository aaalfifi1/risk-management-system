# --- الكود الكامل والنهائي لملف init_db.py ---
# --- متوافق مع نظام الأدوار والصلاحيات (RBAC) ---

import os
from run import app, db, User, Role  # [تعديل] استيراد Role أيضًا

def initialize_database():
    """
    يقوم هذا السكريبت بتهيئة قاعدة البيانات:
    1. يحذف الجداول القديمة ويعيد إنشاءها بالهيكل الجديد.
    2. ينشئ الأدوار الأساسية (Admin, Pioneer, Reporter).
    3. ينشئ المستخدمين الافتراضيين ويربط كل مستخدم بالدور الصحيح.
    """
    print("Starting database initialization with RBAC...")
    with app.app_context():
        # الخطوة 1: حذف الجداول القديمة وإعادة إنشائها
        db.drop_all()
        db.create_all()
        print("Tables dropped and recreated successfully.")

        # الخطوة 2: إنشاء الأدوار الأساسية
        roles_to_create = ['Admin', 'Pioneer', 'Reporter']
        for r_name in roles_to_create:
            if not Role.query.filter_by(name=r_name).first():
                db.session.add(Role(name=r_name))
                print(f"Role '{r_name}' created.")
        
        # حفظ الأدوار في قاعدة البيانات لتكون متاحة للاستعلام
        db.session.commit()
        print("Roles committed to the database.")

        # الخطوة 3: جلب الأدوار من قاعدة البيانات
        admin_role = Role.query.filter_by(name='Admin').first()
        pioneer_role = Role.query.filter_by(name='Pioneer').first()
        reporter_role = Role.query.filter_by(name='Reporter').first()

        # التحقق من وجود الأدوار قبل إنشاء المستخدمين
        if not all([admin_role, pioneer_role, reporter_role]):
            print("ERROR: One or more roles could not be found after creation. Aborting user creation.")
            return

        # الخطوة 4: إنشاء المستخدمين الافتراضيين مع ربطهم بالأدوار
        users_to_create = {
            'admin': ('Admin@2025', 'twag1212@gmail.com', admin_role.id),
            'pioneer': ('Pioneer@1234', 'pioneer@example.com', pioneer_role.id),
            'reporter': ('Reporter@123', 'reporter@example.com', reporter_role.id)
        }

        for username, (password, email, role_id) in users_to_create.items():
            if not User.query.filter_by(username=username).first():
                new_user = User(username=username, email=email, role_id=role_id)
                new_user.set_password(password)
                db.session.add(new_user)
                print(f"User '{username}' with role_id '{role_id}' prepared for creation.")
        
        # حفظ المستخدمين الجدد في قاعدة البيانات
        db.session.commit()
        print("Default users committed to the database.")
        print("Database initialization complete.")

# هذا الجزء يسمح بتشغيل الملف مباشرة من سطر الأوامر
if __name__ == '__main__':
    initialize_database()
