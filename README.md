# Message Encryption/Decryption App

This is a simple GUI application built using the Tkinter library in Python. It allows users to encrypt and decrypt messages using a Caesar cipher, as well as decode encrypted messages by trying all possible keys.

## Features
- Encrypt a message using a key (1-25)
- Decrypt an encrypted message using the corresponding key
- Decode an encrypted message by trying all possible keys (brute-force approach)
- Copy the encrypted, decrypted, or decoded messages to the clipboard

## Requirements
- Python 3.x
- Tkinter (usually included with Python installations)
- pyperclip (for copying text to the clipboard)

## Usage
1. Run the script `message_encryption.py`. The application window will open.
2. Enter the message you want to encrypt, decrypt, or decode in the "Message" field.
3. For encryption and decryption, enter the key (1-25) in the "Key (1-25)" field.
4. Click the "Encrypt" button to encrypt the message using the provided key.
5. Click the "Decrypt" button to decrypt an encrypted message using the provided key.
6. Click the "Decode" button to decode an encrypted message by trying all possible keys (1-25).
7. The encrypted, decrypted, or decoded messages will be displayed in a pop-up window and copied to the clipboard.

## Code Structure
The code consists of the following functions:
- `encrypt(message, key)`: Encrypts the given message using the Caesar cipher with the provided key.
- `decrypt(message, key)`: Decrypts the given message using the Caesar cipher with the provided key.
- `decode(message)`: Tries all possible keys (1-25) to decode the given encrypted message and returns the first 10 decoded messages.
- `on_encrypt()`: Event handler for the "Encrypt" button. Encrypts the message and copies the encrypted text to the clipboard.
- `on_decrypt()`: Event handler for the "Decrypt" button. Decrypts the message and copies the decrypted text to the clipboard.
- `on_decode()`: Event handler for the "Decode" button. Decodes the message by trying all possible keys and copies the first 10 decoded messages to the clipboard.

The Tkinter GUI is created and configured in the last part of the code.

## Note
This application uses a simple Caesar cipher for encryption and decryption, which is not secure for real-world applications. It is intended for educational and demonstration purposes only.

## Source Code
The source code for this project is available on GitHub: https://github.com/AdemGD/ATI03/blob/main/spare.py