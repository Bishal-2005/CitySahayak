# manage_user.py
from app import app, db, User

def list_users():
    with app.app_context():
        print("\n--- All Users ---")
        users = User.query.all()
        if not users:
            print("No users found.")
            return
        for u in users:
            print(f"ID={u.id} | Name={u.name} | Email={u.email}")

def delete_user(email):
    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if not user:
            print(f"❌ User not found: {email}")
            return
        db.session.delete(user)
        db.session.commit()
        print(f"✅ User deleted: {email}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1:
        print("Usage:")
        print("  python manage_user.py list")
        print("  python manage_user.py delete <email>")
    elif sys.argv[1] == "list":
        list_users()
    elif sys.argv[1] == "delete" and len(sys.argv) == 3:
        delete_user(sys.argv[2])
    else:
        print("Invalid command.")
