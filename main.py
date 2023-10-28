from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

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

# User interaction: Generate or load keys
key_choice = input("Generate new keys or use existing keys? (new/existing): ").lower()

if key_choice == "new":
    private_key, public_key = generate_key_pair()
else:
    try:
        with open("private_key.pem", "rb") as private_key_file:
            private_key = serialization.load_pem_private_key(private_key_file.read(), password=None)

        with open("public_key.pem", "rb") as public_key_file:
            public_key = serialization.load_pem_public_key(public_key_file.read())
    except FileNotFoundError:
        print("Key files not found. Please generate new keys.")
        private_key, public_key = generate_key_pair()

# User interaction: Choose between message and file encryption
encrypt_choice = input("Encrypt a message or a file? (message/file): ").lower()

if encrypt_choice == "message":
    # User interaction: Enter a message to encrypt
    message = input("Enter a message to encrypt: ").encode()
    ciphertext = encrypt_message(public_key, message)
    print(f"Encrypted message: {ciphertext}")

    # User interaction: Decrypt the message
    decrypt_choice = input("Decrypt the message? (yes/no): ").lower()

    if decrypt_choice == "yes":
        try:
            decrypted_message = decrypt_message(private_key, ciphertext)
            print(f"Decrypted message: {decrypted_message.decode()}")
        except ValueError:
            print("Decryption failed. Incorrect private key or ciphertext.")
    else:
        print("Message not decrypted.")

elif encrypt_choice == "file":
    # User interaction: Upload a file
    file_path = input("Enter the path of the file to encrypt: ")

    if os.path.exists(file_path):
        with open(file_path, "rb") as file:
            file_content = file.read()

        ciphertext = encrypt_message(public_key, file_content)
        with open("encrypted_file.bin", "wb") as encrypted_file:
            encrypted_file.write(ciphertext)
        print("File encrypted and saved as 'encrypted_file.bin'.")

        decrypt_choice = input("Decrypt the file? (yes/no): ").lower()

        if decrypt_choice == "yes":
            with open("encrypted_file.bin", "rb") as encrypted_file:
                ciphertext = encrypted_file.read()

            try:
                decrypted_message = decrypt_message(private_key, ciphertext)
                with open("decrypted_file.bin", "wb") as decrypted_file:
                    decrypted_file.write(decrypted_message)
                print("File decrypted and saved as 'decrypted_file.bin'.")
            except ValueError:
                print("Decryption failed. Incorrect private key or ciphertext.")
        else:
            print("File not decrypted.")
    else:
        print("File not found.")
