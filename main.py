import logging
import os
import tkinter as tk
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from tkinter import messagebox
from tkinter import ttk

# Configure logging
logging.basicConfig(filename='encryption_app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Function to generate key pair
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("private_key.pem", "wb") as private_key_file:
        private_key_file.write(private_pem)

    with open("public_key.pem", "wb") as public_key_file:
        public_key_file.write(public_pem)

    return private_key, public_key

# Function to encrypt a message
def encrypt_message(public_key, message):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Function to decrypt a message
def decrypt_message(private_key, ciphertext):
    decrypted_message = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message

# Function to toggle dark theme
def toggle_dark_theme():
    current_theme = style.theme_use()
    if current_theme == "light":
        style.theme_use("dark")
    else:
        style.theme_use("light")

# Configure logger
logger = logging.getLogger('encryption_app')

# Create the main window
root = tk.Tk()
root.title("Encryption App")

# Set the style for dark and light themes
style = ttk.Style()
style.theme_use("light")

# Create a frame for the main content
content_frame = ttk.Frame(root, padding=10)
content_frame.grid(row=0, column=0, sticky="nsew")

# Create a dark theme toggle button
dark_theme_button = ttk.Button(content_frame, text="Toggle Dark Theme", command=toggle_dark_theme)
dark_theme_button.grid(row=0, column=0, padx=5, pady=5, sticky="w")

# User interaction: Generate or load keys
key_choice = tk.simpledialog.askstring("Key Choice", "Generate new keys or use existing keys? (new/existing)")

if key_choice == "new":
    private_key, public_key = generate_key_pair()
    logger.info("New key pair generated.")
else:
    try:
        with open("private_key.pem", "rb") as private_key_file:
            private_key = serialization.load_pem_private_key(private_key_file.read(), password=None)

        with open("public_key.pem", "rb") as public_key_file:
            public_key = serialization.load_pem_public_key(public_key_file.read())
        logger.info("Key pair loaded from files.")
    except FileNotFoundError:
        logger.error("Key files not found. Please generate new keys.")
        messagebox.showerror("Error", "Key files not found. Please generate new keys.")
        private_key, public_key = generate_key_pair()

# Run the main loop
root.mainloop()
