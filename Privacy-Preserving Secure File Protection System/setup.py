import os
import sys

print("=== Privacy-Preserving Secure File Protection System ===")


if sys.version_info < (3, 7):
    print("❌ Python 3.7 or higher is required.")
    sys.exit(1)
else:
    print("✔ Python version OK")

# Step 2: Check required folders
folders = ["files", "users"]

for folder in folders:
    if not os.path.exists(folder):
        os.makedirs(folder)
        print(f"✔ Created folder: {folder}")
    else:
        print(f"✔ Folder exists: {folder}")


user_file = "users/users.txt"

if not os.path.exists(user_file):
    with open(user_file, "w") as f:
        f.write("")
    print("✔ User data file initialized")
else:
    print("✔ User data file already exists")

print("\n✅ Setup completed successfully.")
print("You can now run: python main.py")
