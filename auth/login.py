from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json

USERS_FILE = "users_config.json"

class User(UserMixin):
    def __init__(self, id, username, password_hash, role="user", totp_secret=None, totp_enabled=False):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.totp_secret = totp_secret
        self.totp_enabled = totp_enabled

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == "admin"

def _load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            data = json.load(f)
        loaded = {}
        for username, info in data.items():
            loaded[username] = User(
                id=username,
                username=username,
                password_hash=info["password_hash"],
                role=info.get("role", "user"),
                totp_secret=info.get("totp_secret"),
                totp_enabled=info.get("totp_enabled", False)
            )
        return loaded
    else:
        default = {
            "admin": {
                "password_hash": generate_password_hash(os.getenv("ADMIN_PASSWORD", "admin")),
                "role": "admin",
                "totp_secret": None,
                "totp_enabled": False
            }
        }
        with open(USERS_FILE, "w") as f:
            json.dump(default, f, indent=2)
        return {
            "admin": User(
                id="admin",
                username="admin",
                password_hash=default["admin"]["password_hash"],
                role="admin",
                totp_secret=None,
                totp_enabled=False
            )
        }

def _save_users(users_dict):
    data = {}
    for username, user in users_dict.items():
        data[username] = {
            "password_hash": user.password_hash,
            "role": user.role,
            "totp_secret": user.totp_secret,
            "totp_enabled": user.totp_enabled
        }
    with open(USERS_FILE, "w") as f:
        json.dump(data, f, indent=2)

users = _load_users()

def get_user(username):
    return users.get(username)

def get_user_by_id(user_id):
    return users.get(user_id)

def get_all_users():
    return list(users.values())

def register_user(username, password):
    if username in users:
        return False, "Utilizatorul exista deja."
    if len(username) < 3:
        return False, "Username-ul trebuie sa aiba minim 3 caractere."
    if len(password) < 6:
        return False, "Parola trebuie sa aiba minim 6 caractere."
    users[username] = User(
        id=username,
        username=username,
        password_hash=generate_password_hash(password),
        role="user"
    )
    save_users()
    return True, "Cont creat cu succes."

def save_users():
    _save_users(users)
