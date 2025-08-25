import os
from run import app, db, User, Role

def initialize_database():
    print("Starting database initialization with RBAC...")
    with app.app_context():
        db.drop_all()
        db.create_all()
        print("Tables dropped and recreated successfully.")

        # --- 1. إنشاء الأدوار (Roles) ---
        roles_to_create = ['Admin', 'Pioneer', 'Reporter']
        for role_name in roles_to_create:
            if not Role.query.filter_by(name=role_name).first():
                new_role = Role(name=role_name)
                db.session.add(new_role)
        db.session.commit()
        print("Roles committed to the database.")

        # --- 2. إنشاء المستخدمين الافتراضيين وربطهم بالأدوار ---
        users_to_create = [
            {'username': 'admin', 'full_name': 'مدير النظام', 'password': 'Admin@2025', 'email': 'twag1212@gmail.com', 'role': 'Admin'},
            {'username': 'pioneer', 'full_name': 'رائد المخاطر', 'password': 'Pioneer@1234', 'email': 'pioneer@example.com', 'role': 'Pioneer'},
            {'username': 'reporter', 'full_name': 'المبلغ', 'password': 'Reporter@123', 'email': 'reporter@example.com', 'role': 'Reporter'}
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
        print("Default users committed to the database.")
        print("Database initialization complete.")

if __name__ == '__main__':
    initialize_database()
