import customtkinter as ctk
import sqlite3
from cryptography.fernet import Fernet
import os
import pyperclip
import re
import random
import string
import csv

# Initialize the main application window
ctk.set_appearance_mode("dark")  # Use dark mode

# Generate encryption key and store in a file (only run once)
def generate_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)

# Load the encryption key
def load_key():
    return open("secret.key", "rb").read()

# Encrypt the password
def encrypt_password(password):
    key = load_key()
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())
    return encrypted_password

# Decrypt the password
def decrypt_password(encrypted_password):
    key = load_key()
    fernet = Fernet(key)
    decrypted_password = fernet.decrypt(encrypted_password).decode()
    return decrypted_password

# Database setup
def init_db():
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            password BLOB NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Add password to the database, ensuring no duplicates
def add_password(website, username, password):
    encrypted_password = encrypt_password(password)
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()

    # Check for duplicates (same website and username)
    cursor.execute('SELECT * FROM passwords WHERE website = ? AND username = ?', (website, username))
    if cursor.fetchone():
        return "Duplicate"

    cursor.execute('INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)', (website, username, encrypted_password))
    conn.commit()
    conn.close()
    return "Success"

# View saved passwords
def view_passwords():
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, website, username, password FROM passwords')
    data = cursor.fetchall()
    conn.close()
    return data

# Delete a password from the database by ID
def delete_password(password_id):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM passwords WHERE id = ?', (password_id,))
    conn.commit()
    conn.close()

# Copy password to clipboard
def copy_to_clipboard(password):
    decrypted_password = decrypt_password(password)
    pyperclip.copy(decrypted_password)

# Password Strength Checker
def check_password_strength(password):
    if len(password) < 8:
        return "Weak (too short)"
    if not re.search(r'[A-Z]', password):
        return "Weak (no uppercase letters)"
    if not re.search(r'[a-z]', password):
        return "Weak (no lowercase letters)"
    if not re.search(r'[0-9]', password):
        return "Weak (no numbers)"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "Weak (no special characters)"
    return "Strong"

# Random Password Generator
def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

# Export passwords to a CSV file
def export_passwords(file_name="passwords_export.csv"):
    passwords = view_passwords()
    with open(file_name, mode="w", newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["ID", "Website", "Username", "Password"])
        for idx, website, username, encrypted_password in passwords:
            decrypted_password = decrypt_password(encrypted_password)
            writer.writerow([idx, website, username, decrypted_password])

# Import passwords from a CSV file
def import_passwords(file_name="passwords_import.csv"):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    with open(file_name, mode="r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            website = row["Website"]
            username = row["Username"]
            password = encrypt_password(row["Password"])
            cursor.execute('INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)', (website, username, password))
    conn.commit()
    conn.close()

# Initialize UI
class PasswordManagerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Password Manager By TheZ")
        self.geometry("900x800")
        self.iconbitmap("icon.ico")

        self.resizable(False, False)

        # Track password visibility in entry field and list
        self.password_visible = False
        self.show_passwords = False

        # Main frame with black/gray background and red accents
        self.frame = ctk.CTkFrame(self, fg_color="black", border_color="red", border_width=2)
        self.frame.pack(pady=20, padx=20, fill="both", expand=True)

        # Labels and inputs with red borders and text
        self.website_label = ctk.CTkLabel(self.frame, text="Website:", fg_color="black", text_color="red")
        self.website_label.grid(row=0, column=0, padx=10, pady=10)

        self.website_entry = ctk.CTkEntry(self.frame, width=300, fg_color="gray", text_color="white", border_color="red", border_width=2)
        self.website_entry.grid(row=0, column=1, padx=10, pady=10)

        self.username_label = ctk.CTkLabel(self.frame, text="Username:", fg_color="black", text_color="red")
        self.username_label.grid(row=1, column=0, padx=10, pady=10)

        self.username_entry = ctk.CTkEntry(self.frame, width=300, fg_color="gray", text_color="white", border_color="red", border_width=2)
        self.username_entry.grid(row=1, column=1, padx=10, pady=10)

        self.password_label = ctk.CTkLabel(self.frame, text="Password:", fg_color="black", text_color="red")
        self.password_label.grid(row=2, column=0, padx=10, pady=10)

        self.password_entry = ctk.CTkEntry(self.frame, show="*", width=300, fg_color="gray", text_color="white", border_color="red", border_width=2)
        self.password_entry.grid(row=2, column=1, padx=10, pady=10)

        # Show/Hide password button
        self.show_hide_button = ctk.CTkButton(self.frame, text="Show", command=self.toggle_password_visibility, fg_color="red", hover_color="darkred")
        self.show_hide_button.grid(row=2, column=2, padx=10, pady=10)

        # Password Strength Label
        self.strength_label = ctk.CTkLabel(self.frame, text="", fg_color="black", text_color="red")
        self.strength_label.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

        # Check Password Strength Button
        self.check_strength_button = ctk.CTkButton(self.frame, text="Check Password Strength", command=self.check_password_strength, fg_color="red", hover_color="darkred")
        self.check_strength_button.grid(row=4, column=0, padx=10, pady=10)

        # Generate Password Button
        self.generate_button = ctk.CTkButton(self.frame, text="Generate Password", command=self.generate_password, fg_color="red", hover_color="darkred")
        self.generate_button.grid(row=4, column=1, padx=10, pady=10)

        # Add/Search Buttons
        self.add_button = ctk.CTkButton(self.frame, text="Add Password", command=self.add_password, fg_color="red", hover_color="darkred")
        self.add_button.grid(row=5, column=0, padx=10, pady=10)

        self.search_button = ctk.CTkButton(self.frame, text="Search Passwords", command=self.search_passwords, fg_color="red", hover_color="darkred")
        self.search_button.grid(row=5, column=1, padx=10, pady=10)

        # Delete field and button
        self.id_label = ctk.CTkLabel(self.frame, text="Delete ID:", fg_color="black", text_color="red")
        self.id_label.grid(row=6, column=0, padx=10, pady=10)

        self.id_entry = ctk.CTkEntry(self.frame, width=300, fg_color="gray", text_color="white", border_color="red", border_width=2)
        self.id_entry.grid(row=6, column=1, padx=10, pady=10)

        self.delete_button = ctk.CTkButton(self.frame, text="Delete Password", command=self.delete_password, fg_color="red", hover_color="darkred")
        self.delete_button.grid(row=6, column=2, padx=10, pady=10)

        # Output box for search results or password display
        self.output_box = ctk.CTkTextbox(self.frame, width=450, height=200, fg_color="gray", text_color="white", border_color="red", border_width=2)
        self.output_box.grid(row=7, column=0, columnspan=3, padx=10, pady=10)

        # Show/Hide passwords button for the list
        self.show_hide_list_button = ctk.CTkButton(self.frame, text="Show Passwords", command=self.toggle_list_password_visibility, fg_color="red", hover_color="darkred")
        self.show_hide_list_button.grid(row=8, column=0, columnspan=3, padx=10, pady=10)

        # Export/Import Buttons
        self.export_button = ctk.CTkButton(self.frame, text="Export Passwords", command=self.export_passwords, fg_color="red", hover_color="darkred")
        self.export_button.grid(row=9, column=0, padx=10, pady=10)

        self.import_button = ctk.CTkButton(self.frame, text="Import Passwords", command=self.import_passwords, fg_color="red", hover_color="darkred")
        self.import_button.grid(row=9, column=1, padx=10, pady=10)

    def add_password(self):
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        if website and username and password:
            result = add_password(website, username, password)
            if result == "Duplicate":
                self.output_box.insert("0.0", f"Duplicate entry for {website}\n")
            else:
                self.output_box.insert("0.0", f"Added {website}\n")
        else:
            self.output_box.insert("0.0", "Please fill all fields!\n")

    def check_password_strength(self):
        password = self.password_entry.get()
        strength = check_password_strength(password)
        self.strength_label.configure(text=f"Password Strength: {strength}")

    def generate_password(self):
        password = generate_password()
        self.password_entry.delete(0, "end")
        self.password_entry.insert(0, password)

    def search_passwords(self):
        query = self.website_entry.get()
        passwords = view_passwords()
        self.output_box.delete("0.0", "end")
        for idx, website, username, encrypted_password in passwords:
            if query.lower() in website.lower() or query.lower() in username.lower():
                if self.show_passwords:
                    decrypted_password = decrypt_password(encrypted_password)
                    self.output_box.insert("end", f"ID: {idx} | Website: {website} | Username: {username} | Password: {decrypted_password}\n")
                else:
                    self.output_box.insert("end", f"ID: {idx} | Website: {website} | Username: {username} | Password: ********\n")

    def delete_password(self):
        password_id = self.id_entry.get()
        if password_id:
            delete_password(int(password_id))
            self.output_box.insert("0.0", f"Deleted password with ID {password_id}\n")
        else:
            self.output_box.insert("0.0", "Please enter a valid ID!\n")

    def toggle_password_visibility(self):
        if self.password_visible:
            self.password_entry.configure(show="*")
            self.show_hide_button.configure(text="Show")
        else:
            self.password_entry.configure(show="")
            self.show_hide_button.configure(text="Hide")
        self.password_visible = not self.password_visible

    def toggle_list_password_visibility(self):
        self.show_passwords = not self.show_passwords
        self.show_hide_list_button.configure(text="Hide Passwords" if self.show_passwords else "Show Passwords")
        self.search_passwords()

    def export_passwords(self):
        export_passwords()

    def import_passwords(self):
        import_passwords()


if __name__ == "__main__":
    generate_key()  # Generate key only if it doesn't exist
    init_db()       # Initialize the database
    app = PasswordManagerApp()
    app.mainloop()
