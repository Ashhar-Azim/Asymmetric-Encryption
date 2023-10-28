# Asymmetric Encryption App

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [File Structure](#file-structure)
- [Logging](#logging)
- [Contributing](#contributing)

## Overview

The Encryption App is a Python program that allows you to perform asymmetric encryption and decryption of messages and files. It also features a user-friendly graphical interface with a dark theme toggle option. This README provides an overview of the program, its features, and how to use it.

## Features

- **Asymmetric Encryption**: Utilizes the `cryptography` library to perform secure asymmetric encryption and decryption.
- **Graphical User Interface**: Provides a graphical user interface using the `Tkinter` library for user interactions.
- **Dark Theme Toggle**: Allows users to switch between light and dark themes for a customized experience.
- **Key Management**: Supports generating new key pairs and loading existing ones for encryption.

## Installation

1. Clone this repository to your local machine:

       git clone https://github.com/your-username/asymmetric-encryption-app.git

2. Install the required libraries:

       pip install cryptography

3. Run the program:

       python encryption_app.py

## Usage 

1. Choose between generating new keys or using existing ones.
2. Select whether to encrypt a message or a file.
3. Follow the on-screen instructions to interact with the program.
4. Toggle the dark theme if desired.

## File Structure

- `asymmetric-encryption_app.py`: The main program file.
- `private_key.pem` and `public_key.pem`: Key files for encryption.
- `encrypted_file.bin` and `decrypted_file.bin`: Files for encrypted and decrypted content.
- `.gitignore`: Configuration to exclude specific files from version control.

## Logging

All program events and errors are logged to a file named `encryption_app.log` for debugging and monitoring purposes.

## Contributing

Contributions are welcome! If you find issues or have improvements to suggest, please create a pull request or open an issue.

