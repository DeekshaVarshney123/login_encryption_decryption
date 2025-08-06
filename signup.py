# signup.py
from tkinter import messagebox

def register_user(username, password):
    if not username or not password:
        messagebox.showerror("Error", "Fields cannot be empty!")
        return False

    try:
        with open("users.txt", "a+") as file:
            file.seek(0)
            users = file.readlines()
            for user in users:
                existing_username = user.strip().split(":")[0]
                if username == existing_username:
                    messagebox.showerror("Error", "Username already exists!")
                    return False

            file.write(f"{username}:{password}\n")
            messagebox.showinfo("Success", "User registered successfully!")
            return True

    except Exception as e:
        messagebox.showerror("Error", f"Something went wrong!\n{e}")
        return False

