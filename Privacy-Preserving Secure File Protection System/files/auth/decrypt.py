import os
from cryptography.fernet import Fernet
import base64
import hashlib

def generate_key(password):
    password = password.encode()
    key = hashlib.sha256(password).digest()
    return base64.urlsafe_b64encode(key)

def decrypt_file(file_path, password):
    if not os.path.exists(file_path):
        return "File not found"

    key = generate_key(password)
    fernet = Fernet(key)

    try:
        with open(file_path, "rb") as file:
            encrypted_data = file.read()

        decrypted_data = fernet.decrypt(encrypted_data)

        original_file_path = file_path.replace(".enc", "")

        with open(original_file_path, "wb") as file:
            file.write(decrypted_data)

        return original_file_path

    except Exception:
        return "Invalid password or corrupted file"
