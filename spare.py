import tkinter as tk
from tkinter import messagebox
import pyperclip
import random

# Function to encrypt the message using the Caesar Cipher
def encrypt(message, key):
    """Encrypt message with key."""
    result = ''
    for letter in message:
        if letter.isalpha():  # Check if the character is a letter
            num = ord(letter)
            base = ord('A') if letter.isupper() else ord('a')  # Get the base value for uppercase or lowercase
            num = (num - base + key) % 26 + base  # Apply the Caesar Cipher algorithm
            result += chr(num)
        elif letter.isdigit():  # If the character is a digit, keep it as is
            result += letter
        else:  # If the character is neither a letter nor a digit, keep it as is
            result += letter
    return result

# Function to decrypt the message using the Caesar Cipher
def decrypt(message, key):
    """Decrypt message with key."""
    return encrypt(message, -key)  # Decryption is the same as encryption with a negative key

# Function to decode the message by trying all possible keys
def decode(message):
    """Decode message without key."""
    decoded_messages = []
    for key in range(26):  # Try all possible keys from 0 to 25
        decoded_message = decrypt(message, key)
        decoded_messages.append(f"Key {key}: {decoded_message}")
    return decoded_messages

# Function to generate a random key
def generate_random_code():
    random_key = random.randint(1, 25)  # Generate a random key between 1 and 25
    entry_key.delete(0, tk.END)  # Clear the current key entry
    entry_key.insert(0, str(random_key))  # Insert the random key into the entry

# Function to handle the encryption button click
def on_encrypt():
    phrase = entry_message.get()
    key = entry_key.get()
    if phrase.strip() == '' or not key.isdigit() or int(key) < 1 or int(key) > 25:
        messagebox.showerror("Error", "Invalid input. Please enter a message and a key (1 - 25).")
        return
    encrypted_message = encrypt(phrase, int(key))
    pyperclip.copy(encrypted_message)  # Copy the encrypted message to the clipboard
    messagebox.showinfo("Encrypted Message", "Message copied to clipboard:\n\n" + encrypted_message)
    entry_message.delete(0, tk.END)  # Clear the message and key entries
    entry_key.delete(0, tk.END)

# Function to handle the decryption button click
def on_decrypt():
    phrase = entry_message.get()
    key = entry_key.get()
    if phrase.strip() == '' or not key.isdigit() or int(key) < 1 or int(key) > 25:
        messagebox.showerror("Error", "Invalid input. Please enter a message and a key (1 - 25).")
        return
    decrypted_message = decrypt(phrase, int(key))
    pyperclip.copy(decrypted_message)  # Copy the decrypted message to the clipboard
    messagebox.showinfo("Decrypted Message", "Message copied to clipboard:\n\n" + decrypted_message)
    entry_message.delete(0, tk.END)  # Clear the message and key entries
    entry_key.delete(0, tk.END)

# Function to handle the decoding button click
def on_decode():
    phrase = entry_message.get()
    if phrase.strip() == '':
        messagebox.showerror("Error", "Invalid input. Please enter a message.")
        return

    decrypted_messages = []
    for key in range(26):  # Try all possible keys from 0 to 25
        decrypted_message = decrypt(phrase, key)
        decrypted_messages.append(f"Key {key}: {decrypted_message}")

    decoded_message_str = "\n".join(decrypted_messages)
    pyperclip.copy(decoded_message_str)  # Copy the decoded messages to the clipboard
    messagebox.showinfo("Decrypted Messages", "All possible decrypted messages copied to clipboard:\n\n" + decoded_message_str)
    entry_message.delete(0, tk.END)  # Clear the message entry

# Create the main window
root = tk.Tk()
root.title("Message Encryption")
root.configure(bg="dark gray")

# Create labels and entries for message and key
label_message = tk.Label(root, text="Message:", font=("Arial", 14))
label_message.grid(row=0, column=0, padx=5, pady=5)
entry_message = tk.Entry(root, font=("Arial", 14))
entry_message.grid(row=0, column=1, padx=5, pady=5)

label_key = tk.Label(root, text="Key (1 - 25):", font=("Arial", 14))
label_key.grid(row=1, column=0, padx=5, pady=5)
entry_key = tk.Entry(root, font=("Arial", 14))
entry_key.grid(row=1, column=1, padx=5, pady=5)

# Create buttons for encryption, decryption, decoding, and random key generation
button_encrypt = tk.Button(root, text="Encrypt", command=on_encrypt, bg="light gray", font=("Garamond", 14), relief=tk.RIDGE)
button_encrypt.grid(row=2, column=0, padx=5, pady=5)

button_decrypt = tk.Button(root, text="Decrypt", command=on_decrypt, bg="light gray", font=("Garamond", 14), relief=tk.RIDGE)
button_decrypt.grid(row=2, column=1, padx=5, pady=5)

button_decode = tk.Button(root, text="Decode", command=on_decode, bg="light gray", font=("Garamond", 14), relief=tk.RIDGE)
button_decode.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

button_generate = tk.Button(root, text="Generate Random Code", command=generate_random_code, bg="light gray", font=("Garamond", 14), relief=tk.RIDGE)
button_generate.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

# Start the main event loop
root.mainloop()