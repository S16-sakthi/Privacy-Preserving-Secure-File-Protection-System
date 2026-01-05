import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
USER_FILE = os.path.join(BASE_DIR, "users", "users.txt")


def login_user(username, password):
    if not username or not password:
        return "All fields are required"

    if not os.path.exists(USER_FILE):
        return "No users registered"

    with open(USER_FILE, "r") as f:
        for line in f:
            user, pwd = line.strip().split(",")
            if user == username and pwd == password:
                return "SUCCESS"

    return "Invalid username or password"


def reset_password(username, new_password):
    if not username or not new_password:
        return "All fields are required"

    if not os.path.exists(USER_FILE):
        return "No users registered"

    updated = False
    lines = []

    with open(USER_FILE, "r") as f:
        for line in f:
            user, pwd = line.strip().split(",")
            if user == username:
                lines.append(f"{username},{new_password}\n")
                updated = True
            else:
                lines.append(line)

    if not updated:
        return "User not found"

    with open(USER_FILE, "w") as f:
        f.writelines(lines)

    return "SUCCESS"
