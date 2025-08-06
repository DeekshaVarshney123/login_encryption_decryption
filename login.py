# login.py
from tkinter import messagebox

def check_login(username, password):
    try:
        with open("users.txt", "r") as file:
            users = file.readlines()
            for user in users:
                saved_username, saved_password = user.strip().split(":")
                if username == saved_username and password == saved_password:
                    return True
    except FileNotFoundError:
        messagebox.showerror("Error", "User data not found!")

    messagebox.showerror("Failed", "Invalid Username or Password")
    return False

