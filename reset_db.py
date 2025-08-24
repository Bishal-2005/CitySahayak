import os
from app import db, User, bcrypt, app  # ensure app, db, User, bcrypt properly imported

# Path of your database
db_path = 'citysahayak.db'

# Delete old DB
if os.path.exists(db_path):
    os.remove(db_path)
    print("Old database deleted")

# Create new DB and tables
with app.app_context():
    db.create_all()
    print("New database created")

    # Create admin user
    admin_password = bcrypt.generate_password_hash("admin123").decode('utf-8')
    admin_user = User(
        name="Admin_Bishal",
        email="admincitysahayak@gmail.com",
        password=admin_password
    )
    db.session.add(admin_user)
    db.session.commit()
    print("Admin user created successfully")
