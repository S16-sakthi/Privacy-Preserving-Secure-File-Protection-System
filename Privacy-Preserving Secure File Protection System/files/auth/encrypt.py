import os
from cryptography.fernet import Fernet
import base64
import hashlib

def generate_key(password):
    password = password.encode()
    key = hashlib.sha256(password).digest()
    return base64.urlsafe_b64encode(key)

def encrypt_file(file_path, password):
    if not os.path.exists(file_path):
        return "File not found"

    key = generate_key(password)
    fernet = Fernet(key)

    with open(file_path, "rb") as file:
        original_data = file.read()

    encrypted_data = fernet.encrypt(original_data)

    encrypted_file_path = file_path + ".enc"

    with open(encrypted_file_path, "wb") as file:
        file.write(encrypted_data)

    return encrypted_file_path

