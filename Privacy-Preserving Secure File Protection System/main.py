import os
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, filedialog
from files.auth.login import login_user ,reset_password
from files.auth.encrypt import encrypt_file
from files.auth.decrypt import decrypt_file
from files.auth.register import register_user
login_frame = None
launch_frame = None

TITLE_FONT = ("Arial", 26, "bold")
LABEL_FONT = ("Arial", 14)
ENTRY_FONT = ("Arial", 14)
BUTTON_FONT = ("Arial", 14, "bold")
LINK_FONT = ("Arial", 12)


HISTORY_FILE = "history.txt"

def open_history_screen():
    history_win = tk.Toplevel()
    history_win.title("Encryption History")
    history_win.geometry("700x400")
    history_win.resizable(True, True)

    container = tk.Frame(history_win, padx=20, pady=20)
    container.pack(expand=True, fill="both")

    tk.Label(
        container,
        text="Encryption / Decryption History",
        font=("Arial", 16, "bold")
    ).pack(pady=10)

    history_box = tk.Text(
        container,
        font=("Consolas", 11),
        state="disabled",
        wrap="word"
    )
    history_box.pack(expand=True, fill="both", pady=10)

    def load_history():
        history_box.config(state="normal")
        history_box.delete("1.0", "end")

        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, "r") as f:
                content = f.read().strip()
                history_box.insert("end", content if content else "No history available.")
        else:
            history_box.insert("end", "No history available.")

        history_box.config(state="disabled")

    def clear_history():
        if os.path.exists(HISTORY_FILE):
            open(HISTORY_FILE, "w").close()

        history_box.config(state="normal")
        history_box.delete("1.0", "end")
        history_box.insert("end", "History cleared.")
        history_box.config(state="disabled")

    # Buttons
    btn_frame = tk.Frame(container)
    btn_frame.pack(pady=10)

    tk.Button(
        btn_frame,
        text="Clear History",
        font=("Arial", 12),
        width=18,
        command=clear_history
    ).pack(side="left", padx=10)

    tk.Button(
        btn_frame,
        text="Close",
        font=("Arial", 12),
        width=18,
        command=history_win.destroy
    ).pack(side="left", padx=10)

    load_history()


#login screen
def open_login_screen():
    global login_frame, entry_username, entry_password

    if launch_frame:
        launch_frame.destroy()

    login_frame = tk.Frame(root)
    login_frame.pack(expand=True)

    tk.Label(
        login_frame,
        text="Login",
        font=TITLE_FONT
    ).pack(pady=20)

    tk.Label(login_frame, text="Username", font=LABEL_FONT).pack(pady=(10, 5))
    entry_username = tk.Entry(
        login_frame,
        font=ENTRY_FONT,
        width=30
    )
    entry_username.pack(ipady=6)

    tk.Label(login_frame, text="Password", font=LABEL_FONT).pack(pady=(15, 5))
    entry_password = tk.Entry(
        login_frame,
        font=ENTRY_FONT,
        show="*",
        width=30
    )
    entry_password.pack(ipady=6)

    tk.Button(
        login_frame,
        text="Login",
        font=BUTTON_FONT,
        width=20,
        height=2,
        command=handle_login
    ).pack(pady=25)

    tk.Button(
        login_frame,
        text="Forgot Password?",
        font=LINK_FONT,
        fg="blue",
        borderwidth=0,
        command=open_forgot_password
    ).pack()

    tk.Button(
        login_frame,
        text="New User? Register",
        font=LINK_FONT,
        fg="green",
        borderwidth=5,
        command=open_register
    ).pack(pady=10)

   
#launch screen
def open_launch_screen():
    global launch_frame

    launch_frame = tk.Frame(root)
    launch_frame.pack(expand=True, fill="both")
    root.state("zoomed")
    root.resizable(True, True)

    container = tk.Frame(launch_frame, padx=30, pady=30)
    container.place(relx=0.5, rely=0.5, anchor="center")

    tk.Label(
        container,
        text="Privacy-Preserving Secure File Protection System",
        font=("Arial", 32, "bold"),
        justify="center"
    ).pack(pady=30)

    tk.Label(
        container,
        text=" • Secure • Private • Local Encryption&Decryption",
        font=("Arial", 16)
    ).pack(pady=10)

    tk.Button(
        container,
        text="Launch the App",
        width=25,
        height=2,
        font=("Arial", 12, "bold"),
        command=open_login_screen

    ).pack(pady=25)

# -------- DASHBOARD FUNCTION (FIRST) --------
def open_dashboard():
    dashboard = tk.Toplevel(root)
    dashboard.title("Secure File Dashboard")
    dashboard.state("zoomed")
    dashboard.resizable(True, True)

    container = tk.Frame(dashboard, padx=50, pady=40)
    container.pack(expand=True)

    # ---------- TITLE ----------
    tk.Label(
        container,
        text="Privacy-Preserving Secure File Protection System",
        font=("Arial", 26, "bold")
    ).pack(pady=25)

    # ---------- FILE ENCRYPTION PASSWORD ----------
    tk.Label(
        container,
        text="File Encryption Password",
        font=("Arial", 15, "bold")
    ).pack(pady=(10, 6))

    file_password_entry = tk.Entry(
        container,
        font=("Arial", 14),
        show="*",
        width=42
    )
    file_password_entry.pack(ipady=6)

    strength_label = tk.Label(
        container,
        text="Password strength: ",
        font=("Arial", 11),
        fg="gray"
    )
    strength_label.pack(pady=(6, 18))

    # ---------- BUTTONS (INITIALLY DISABLED) ----------
    encrypt_file_btn = tk.Button(
        container, text="Encrypt File", font="Arial",width=32, height=2, state="disabled"
    )
    encrypt_image_btn = tk.Button(
        container, text="Encrypt Image", font="Arial",width=32, height=2, state="disabled"
    )
    decrypt_btn = tk.Button(
        container, text="Decrypt File / Image", font ="Arial" ,width=32, height=2, state="disabled"
    )

    encrypt_file_btn.pack(pady=6)
    encrypt_image_btn.pack(pady=6)
    decrypt_btn.pack(pady=6)

    # ---------- ACTIONS ----------
    def encrypt_action(file_type="file"):
        if file_type == "image":
            file_path = filedialog.askopenfilename(
                title="Select Image",
                filetypes=[("Image Files", "*.png *.jpg *.jpeg *.bmp")]
            )
        else:
            file_path = filedialog.askopenfilename(title="Select File")

        if not file_path:
            return

        password = file_password_entry.get()
        if not password:
            messagebox.showerror("Error", "Password required")
            return

        result = encrypt_file(file_path, password)
        messagebox.showinfo("Success", f"Encrypted Successfully:\n{result}")
        log_history("ENCRYPT", os.path.basename(file_path))

    def decrypt_action():
        file_path = filedialog.askopenfilename(
            title="Select Encrypted File",
            filetypes=[("Encrypted Files", "*.enc")]
        )

        if not file_path:
            return

        password = file_password_entry.get()
        if not password:
            messagebox.showerror("Error", "Password required")
            return

        result = decrypt_file(file_path, password)
        messagebox.showinfo("Success", f"Decrypted Successfully:\n{result}")
        log_history("DECRYPT", os.path.basename(file_path))

    encrypt_file_btn.config(command=lambda: encrypt_action("file"))
    encrypt_image_btn.config(command=lambda: encrypt_action("image"))
    decrypt_btn.config(command=decrypt_action)

    # ---------- PASSWORD CHECK ----------
    def check_password(event=None):
        pwd = file_password_entry.get()

        if not pwd:
            encrypt_file_btn.config(state="disabled")
            encrypt_image_btn.config(state="disabled")
            decrypt_btn.config(state="disabled")
            strength_label.config(text="Password strength: ", fg="gray")
            return

        encrypt_file_btn.config(state="normal")
        encrypt_image_btn.config(state="normal")
        decrypt_btn.config(state="normal")

        if len(pwd) < 4:
            strength_label.config(text="Password strength: Weak", fg="red")
        elif len(pwd) < 8:
            strength_label.config(text="Password strength: Medium", fg="orange")
        else:
            strength_label.config(text="Password strength: Strong", fg="green")

    file_password_entry.bind("<KeyRelease>", check_password)

    # ---------- HISTORY ----------
    tk.Button(
        container,
        text="View Encryption History",
        font=("Arial", 14, "bold"),
        width=30,
        height=2,
        command=open_history_screen
    ).pack(pady=18)


    # ---------- LOGOUT ----------
    tk.Button(
        container,
        text="Logout",
        font=("Arial", 14),
        width=22,
        height=2,
        command=lambda: (dashboard.destroy(), root.deiconify())
    ).pack(pady=30)



def open_forgot_password():
    fp = tk.Toplevel()
    fp.title("Forgot Password")
    fp.geometry("350x350")
    fp.resizable(True, True)

    container = tk.Frame(fp, padx=20, pady=20)
    container.pack(expand=True, fill="both")

    tk.Label(container, text="Reset Password",
             font=("Arial", 14, "bold")).pack(pady=10)

    tk.Label(container, text="Username").pack()
    username_entry = tk.Entry(container, width=30)
    username_entry.pack(pady=5)

    tk.Label(container, text="New Password").pack()
    new_password_entry = tk.Entry(container, show="*", width=30)
    new_password_entry.pack(pady=5)

    def handle_reset():
        username = username_entry.get()
        new_password = new_password_entry.get()

        result = reset_password(username, new_password)

        if result == "SUCCESS":
            messagebox.showinfo("Success", "Password updated successfully")
            fp.destroy()
        else:
            messagebox.showerror("Error", result)

    tk.Button(container, text="Reset Password",
              width=20, command=handle_reset).pack(pady=15)

def open_register():
    reg = tk.Toplevel()
    reg.title("Register")
    reg.geometry("350x350")
    reg.resizable(True, True)

    container = tk.Frame(reg, padx=20, pady=20)
    container.pack(expand=True, fill="both")

    tk.Label(container, text="Register",
             font=("Arial", 14, "bold")).pack(pady=10)

    tk.Label(container, text="Username").pack()
    username_entry = tk.Entry(container, width=30)
    username_entry.pack(pady=5)

    tk.Label(container, text="Password").pack()
    password_entry = tk.Entry(container, show="*", width=30)
    password_entry.pack(pady=5)

    def handle_register():
        username = username_entry.get()
        password = password_entry.get()

        result = register_user(username, password)

        if result == "SUCCESS":
            messagebox.showinfo("Success", "Registration successful")
            reg.destroy()
        else:
            messagebox.showerror("Error", result)

    tk.Button(container, text="Register",
              width=20, command=handle_register).pack(pady=15)


# -------- LOGIN FUNCTION (SECOND) --------
def handle_login():
    username = entry_username.get()
    password = entry_password.get()

    result = login_user(username, password)

    if result == "SUCCESS":
        messagebox.showinfo("Success", "Login successful")
        root.withdraw()
        open_dashboard()
    else:
        messagebox.showerror("Error", result)

# -------- GUI CODE (LAST) --------


root = tk.Tk()
root.title("Privacy-Preserving Secure File Protection System")
root.geometry("900x600")
root.resizable(True, True)
try:
    root.state("zoomed")
except:
    pass


open_launch_screen()

root.mainloop()


