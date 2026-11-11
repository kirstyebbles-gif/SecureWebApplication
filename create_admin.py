
from getpass import getpass
from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    username = input("Admin username: ").strip()
    email = input("Admin email: ").strip().lower()

    password = getpass("Admin password (minimum 12 characters): ")
    confirm_password = getpass("Confirm admin password: ")

    if len(password) < 12:
        print("Password must be at least 12 characters.")
    elif password != confirm_password:
        print("Passwords do not match.")
    elif User.query.filter(
        (User.username == username) | (User.email == email)
    ).first():
        print("That username or email is already registered.")
    else:
        admin = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            role="admin"
        )

        db.session.add(admin)
        db.session.commit()

        print("Administrator account created successfully.")

