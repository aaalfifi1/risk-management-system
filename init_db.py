from run import app, db, User, Role # استيراد النماذج من ملف run.py

# هذا الملف سيقوم بحذف قاعدة البيانات الحالية وإعادة إنشائها
# استخدمه بحذر في بيئة التطوير فقط، وليس في البيئة الإنتاجية

with app.app_context():
    print("Starting database initialization...")

    # حذف جميع الجداول الحالية
    print("Dropping all tables...")
    db.drop_all()
    print("Tables dropped.")

    # إنشاء جميع الجداول الجديدة بناءً على النماذج (Models)
    print("Creating all tables...")
    db.create_all()
    print("Tables created.")

    # --- 1. إنشاء الأدوار (Roles) ---
    print("Creating roles: Admin, Pioneer, Reporter...")
    roles_to_create = ['Admin', 'Pioneer', 'Reporter']
    for role_name in roles_to_create:
        if not Role.query.filter_by(name=role_name).first():
            db.session.add(Role(name=role_name))
    db.session.commit()
    print("Roles created successfully.")

    # --- 2. إنشاء المستخدمين الافتراضيين وربطهم بالأدوار ---
    print("Creating default users: admin, pioneer, reporter...")
    
    # جلب الأدوار من قاعدة البيانات
    admin_role = Role.query.filter_by(name='Admin').first()
    pioneer_role = Role.query.filter_by(name='Pioneer').first()
    reporter_role = Role.query.filter_by(name='Reporter').first()

    # قاموس المستخدمين لإنشائهم
    users_to_create = {
        'admin': ('Admin@2025', 'twag1212@gmail.com', admin_role),
        'pioneer': ('Pioneer@1234', 'pioneer@example.com', pioneer_role),
        'reporter': ('Reporter@123', 'reporter@example.com', reporter_role)
    }

    for username, (password, email, role) in users_to_create.items():
        # التأكد من عدم وجود المستخدم مسبقًا
        if not User.query.filter_by(username=username).first():
            if role: # التأكد من أن الدور موجود
                # --- [التصحيح الحاسم هنا] ---
                # تم حذف full_name من هنا لأنه غير موجود في نموذج User
                new_user = User(username=username, email=email, role_id=role.id)
                new_user.set_password(password)
                db.session.add(new_user)
            else:
                print(f"Warning: Role for user '{username}' not found. User not created.")

    # حفظ جميع المستخدمين الجدد في قاعدة البيانات
    db.session.commit()
    print("Default users created successfully.")

    print("Database has been successfully initialized with new data.")
