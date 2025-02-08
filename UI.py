import tkinter as tk
from tkinter import ttk, messagebox

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Cipher Vault")
        self.root.geometry("400x300")
        self.root.configure(bg="#f0f0f0")

        self.users = {
            "mahendra":"mahendra"
        }  # Simulated user database
        self.current_user = None

        self.show_login_page()

    def show_login_page(self):
        self.clear_window()
        self.root.geometry("400x300")

        # Title
        title_label = ttk.Label(self.root, text="Login", font=("Helvetica", 16), background="#f0f0f0")
        title_label.pack(pady=20)

        # Username
        username_label = ttk.Label(self.root, text="Username:", background="#f0f0f0")
        username_label.pack()
        self.username_entry = ttk.Entry(self.root, width=30)
        self.username_entry.pack(pady=5)

        # Password
        password_label = ttk.Label(self.root, text="Password:", background="#f0f0f0")
        password_label.pack()
        self.password_entry = ttk.Entry(self.root, width=30, show="*")
        self.password_entry.pack(pady=5)

        # Login Button
        login_button = ttk.Button(self.root, text="Login", command=self.login)
        login_button.pack(pady=10)

        # Signup Link
        signup_label = ttk.Label(self.root, text="Don't have an account? Sign up", cursor="hand2", background="#f0f0f0")
        signup_label.pack(pady=5)
        signup_label.bind("<Button-1>", lambda e: self.show_signup_page())

    def show_signup_page(self):
        self.clear_window()
        self.root.geometry("400x300")

        # Title
        title_label = ttk.Label(self.root, text="Sign Up", font=("Helvetica", 16), background="#f0f0f0")
        title_label.pack(pady=20)

        # Username
        username_label = ttk.Label(self.root, text="Username:", background="#f0f0f0")
        username_label.pack()
        self.signup_username_entry = ttk.Entry(self.root, width=30)
        self.signup_username_entry.pack(pady=5)

        # Password
        password_label = ttk.Label(self.root, text="Password:", background="#f0f0f0")
        password_label.pack()
        self.signup_password_entry = ttk.Entry(self.root, width=30, show="*")
        self.signup_password_entry.pack(pady=5)

        # Confirm Password
        confirm_password_label = ttk.Label(self.root, text="Confirm Password:", background="#f0f0f0")
        confirm_password_label.pack()
        self.confirm_password_entry = ttk.Entry(self.root, width=30, show="*")
        self.confirm_password_entry.pack(pady=5)

        # Signup Button
        signup_button = ttk.Button(self.root, text="Sign Up", command=self.signup)
        signup_button.pack(pady=10)

        # Login Link
        login_label = ttk.Label(self.root, text="Already have an account? Login", cursor="hand2", background="#f0f0f0")
        login_label.pack(pady=5)
        login_label.bind("<Button-1>", lambda e: self.show_login_page())

    def show_password_page(self):
        self.clear_window()
        self.root.geometry("600x400")

        # Title
        title_label = ttk.Label(self.root, text="Saved Passwords", font=("Helvetica", 16), background="#f0f0f0")
        title_label.pack(pady=20)

        # Treeview to display passwords
        columns = ("Website", "Username", "Password")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
        self.tree.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        # Add some sample data
        self.tree.insert("", "end", values=("example.com", "user123", "password123"))
        self.tree.insert("", "end", values=("test.com", "testuser", "testpassword"))

        # Logout Button
        logout_button = ttk.Button(self.root, text="Logout", command=self.logout)
        logout_button.pack(pady=10)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username in self.users and self.users[username] == password:
            self.current_user = username
            self.show_password_page()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def signup(self):
        username = self.signup_username_entry.get()
        password = self.signup_password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        if password != confirm_password:
            messagebox.showerror("Signup Failed", "Passwords do not match")
            return

        if username in self.users:
            messagebox.showerror("Signup Failed", "Username already exists")
            return

        self.users[username] = password
        messagebox.showinfo("Signup Successful", "Account created successfully")
        self.show_login_page()

    def logout(self):
        self.current_user = None
        self.show_login_page()

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()