import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
USER_FILE = os.path.join(BASE_DIR, "users", "users.txt")

def register_user(username, password):
    if not username or not password:
        return "All fields are required"

    os.makedirs(os.path.dirname(USER_FILE), exist_ok=True)

    if os.path.exists(USER_FILE):
        with open(USER_FILE, "r") as f:
            for line in f:
                if line.split(",")[0] == username:
                    return "User already exists"

    with open(USER_FILE, "a") as f:
        f.write(f"{username},{password}\n")

    return "SUCCESS"
