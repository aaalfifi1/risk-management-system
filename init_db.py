# هذا الملف مخصص لتهيئة قاعدة البيانات على Render
import os
from run import app, db, User
from werkzeug.security import generate_password_hash
from sqlalchemy import inspect

print(">>>> SCRIPT init_db.py: STARTING DATABASE INITIALIZATION...")

db_url = os.environ.get('DATABASE_URL')
if not db_url:
    print("!!!! SCRIPT init_db.py: ERROR - DATABASE_URL not found.")
    exit(1)

try:
    with app.app_context():
        inspector = inspect(db.engine)
        
        if not inspector.has_table("user"):
            print(">>>> SCRIPT init_db.py: 'user' table not found. Creating all tables...")
            db.create_all()
            print(">>>> SCRIPT init_db.py: Tables created successfully.")
        else:
            print(">>>> SCRIPT init_db.py: 'user' table already exists. Skipping table creation.")

        users_to_create = {'admin': 'Admin@2025', 'testuser': 'Test@1234', 'reporter': 'Reporter@123'}
        for username, password in users_to_create.items():
            if not User.query.filter_by(username=username).first():
                new_user = User(username=username, password_hash=generate_password_hash(password))
                db.session.add(new_user)
                print(f">>>> SCRIPT init_db.py: Creating user '{username}'...")
        
        db.session.commit()
        print(">>>> SCRIPT init_db.py: Default users checked/created. Commit successful.")

except Exception as e:
    print(f"!!!! SCRIPT init_db.py: AN ERROR OCCURRED: {e}")
    import traceback
    traceback.print_exc()
    exit(1)

print(">>>> SCRIPT init_db.py: DATABASE INITIALIZATION COMPLETE.")
