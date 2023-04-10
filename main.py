import random
import tkinter as tk
from tkinter import messagebox


def copy_password():
    if password == "":
        messagebox.showerror("Error", "No password to copy.\nTry generating a password first.")
    else:
        try:
            root.clipboard_clear()
            root.clipboard_append(password)
            messagebox.showinfo("Password Copied", "Password copied to clipboard!")
        except:
            messagebox.showerror("Error", "An error occurred while copying password to clipboard.")
def password_generator():
    global password
    global password_length
    global password_characters
    password = ""

    try:
        password_length = int(password_length_entry.get())
        if password_length < 8 or password_length > 16:
            raise ValueError("Invalid password length. Password length must be between 8 and 16.")
    except ValueError as e:
        password_label.configure(text=str(e))
        return

    try:
        for i in range(password_length):
            password += random.choice(password_characters)
        password_label.configure(text=password)
    except Exception as e:
        password_label.configure(text="An error occurred while generating password.")
        return

#variables
password = ""
password_length = 0
password_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+"

#root
root = tk.Tk()
root.title("Password Maker")
root.geometry("500x300")
root.configure(bg="black")
root.resizable(False, False)
root.iconbitmap("icon.ico") #https://icon-icons.com/icon/eye/251996

#move this button down below the password label
d = tk.Button(root, text="Copy Password", font=("Arial", 10), bg="black", fg="white", command=lambda: copy_password())
d.pack()


#password length label and entry
password_length_label = tk.Label(root, text="Password Length:", font=("Arial", 10), bg="black", fg="white")
password_length_label.pack()
password_length_entry = tk.Entry(root, font=("Arial", 10))
password_length_entry.pack()

#generate password button
button = tk.Button(root, text="Generate Password", font=("Arial", 10), bg="black", fg="white", command=lambda: password_generator())
button.pack()

#password label
password_label = tk.Label(root, text="", font=("Arial", 10), bg="black", fg="white")
password_label.pack()

#loop
root.mainloop()
