import tkinter as tk
from tkinter import messagebox
import base64

from signup import register_user
from login import check_login

def clear_entries(*entries):
    """Clear text in all given Entry widgets"""
    for entry in entries:
        entry.delete(0, tk.END)

def show_frame(frame):
    """Hide all frames and show only the selected frame"""
    for f in [signup_frame, login_frame, choice_frame, encrypt_frame, decrypt_frame]:
        f.pack_forget()
    frame.pack(pady=20)

# Signup button action
def handle_signup():
    username = s_username.get().strip()
    password = s_password.get().strip()
    if register_user(username, password):
        clear_entries(s_username, s_password)
        show_frame(login_frame)

# Login button action
def handle_login():
    username = l_username.get().strip()
    password = l_password.get().strip()
    if check_login(username, password):
        clear_entries(l_username, l_password)
        welcome_label.config(text=f"Welcome, {username}!")
        show_frame(choice_frame)

# When user selects Encrypt option
def choose_encrypt():
    # Clear previous text and encrypted output
    text_area.delete("1.0", tk.END)
    encrypted_text_widget.config(state="normal")
    encrypted_text_widget.delete("1.0", tk.END)
    encrypted_text_widget.config(state="disabled")
    show_frame(encrypt_frame)

# When user selects Decrypt option
def choose_decrypt():
    # Clear decrypted output
    decrypted_label.config(text="")
    show_frame(decrypt_frame)

# Encrypt the entered text and show encrypted result
def encrypt_and_show():
    raw_text = text_area.get("1.0", "end-1c").strip()
    if raw_text == "":
        messagebox.showwarning("Empty", "Please enter some text to encrypt.")
        return
    encoded = base64.b64encode(raw_text.encode()).decode()
    encrypted_text_widget.config(state="normal")
    encrypted_text_widget.delete("1.0", tk.END)
    encrypted_text_widget.insert(tk.END, encoded)
    encrypted_text_widget.config(state="disabled")

# Decrypt the encrypted text and show decrypted result
def decrypt_and_show():
    encoded_text = encrypted_text_widget_decrypt.get("1.0", "end-1c").strip()
    if encoded_text == "":
        messagebox.showwarning("Empty", "No encrypted text to decrypt.")
        return
    try:
        decoded_bytes = base64.b64decode(encoded_text)
        decoded_text = decoded_bytes.decode()
        decrypted_label.config(text=decoded_text)
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

# Logout user and return to login screen
def logout():
    welcome_label.config(text="")
    show_frame(login_frame)

# Create main window
window = tk.Tk()
window.title("Secure Notes App")
window.geometry("500x450")
window.config(bg="lightgray")

# ----------------- Signup Frame -------------------
signup_frame = tk.Frame(window, bg="lightblue")
tk.Label(signup_frame, text="Sign Up", font=("Arial", 16), bg="lightblue").pack(pady=10)
s_username = tk.Entry(signup_frame, width=30)
s_username.pack(pady=5)
s_password = tk.Entry(signup_frame, width=30, show="*")
s_password.pack(pady=5)
tk.Button(signup_frame, text="Register", command=handle_signup).pack(pady=5)
tk.Button(signup_frame, text="Go to Login", command=lambda: show_frame(login_frame)).pack()

# ----------------- Login Frame --------------------
login_frame = tk.Frame(window, bg="lightgreen")
tk.Label(login_frame, text="Login", font=("Arial", 16), bg="lightgreen").pack(pady=10)
l_username = tk.Entry(login_frame, width=30)
l_username.pack(pady=5)
l_password = tk.Entry(login_frame, width=30, show="*")
l_password.pack(pady=5)
tk.Button(login_frame, text="Login", command=handle_login).pack(pady=5)
tk.Button(login_frame, text="Go to Signup", command=lambda: show_frame(signup_frame)).pack()

# ----------------- Choice Frame -------------------
choice_frame = tk.Frame(window, bg="lightyellow")
welcome_label = tk.Label(choice_frame, text="", font=("Arial", 14), bg="lightyellow")
welcome_label.pack(pady=10)
tk.Label(choice_frame, text="Choose an option:", font=("Arial", 12), bg="lightyellow").pack(pady=10)
tk.Button(choice_frame, text="Encrypt Text", width=20, command=choose_encrypt).pack(pady=5)
tk.Button(choice_frame, text="Decrypt Text", width=20, command=choose_decrypt).pack(pady=5)
tk.Button(choice_frame, text="Logout", width=20, command=logout).pack(pady=20)

# ----------------- Encrypt Frame -------------------
encrypt_frame = tk.Frame(window, bg="white")
tk.Label(encrypt_frame, text="Enter text to encrypt:", font=("Arial", 14), bg="white").pack(pady=10)
text_area = tk.Text(encrypt_frame, height=5, width=40)
text_area.pack(pady=5)
tk.Button(encrypt_frame, text="Encrypt & Show", command=encrypt_and_show).pack(pady=5)

# This Text widget will show encrypted text and allow copying
encrypted_text_widget = tk.Text(encrypt_frame, height=5, width=50, wrap="word")
encrypted_text_widget.pack(pady=10)
encrypted_text_widget.config(state="disabled")  # Disable editing, allow copy

tk.Button(encrypt_frame, text="Back to Choice", command=lambda: show_frame(choice_frame)).pack(pady=5)

# ----------------- Decrypt Frame -------------------
decrypt_frame = tk.Frame(window, bg="white")
tk.Label(decrypt_frame, text="Encrypted text to decrypt:", font=("Arial", 14), bg="white").pack(pady=10)

# This Text widget shows encrypted text to decrypt (copyable, non-editable)
encrypted_text_widget_decrypt = tk.Text(decrypt_frame, height=5, width=50, wrap="word")
encrypted_text_widget_decrypt.pack(pady=5)
encrypted_text_widget_decrypt.config(state="normal")


# Label to show decrypted text result
decrypted_label = tk.Label(decrypt_frame, text="", bg="white", fg="green", wraplength=400, font=("Arial", 12))
decrypted_label.pack(pady=10)

tk.Button(decrypt_frame, text="Decrypt & Show", command=decrypt_and_show).pack(pady=5)
tk.Button(decrypt_frame, text="Back to Choice", command=lambda: show_frame(choice_frame)).pack(pady=5)


# Show signup frame initially
show_frame(signup_frame)

window.mainloop()
