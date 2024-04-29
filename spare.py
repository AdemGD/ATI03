import tkinter as tk
from tkinter import messagebox, filedialog
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

# Function to open a file and process its contents
def process_file():
    file_path = filedialog.askopenfilename(title="Select a file", filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, 'r') as file:
            file_contents = file.read()
        operation = tk.simpledialog.askstring("Operation", "What would you like to do with the file contents?\nEncrypt, Decrypt, or Decode?", parent=root)
        if operation is not None:
            operation = operation.lower()
            if operation == "encrypt":
                key = tk.simpledialog.askinteger("Encryption Key", "Enter a key (1 - 25):", parent=root, minvalue=1, maxvalue=25)
                if key is not None:
                    encrypted_contents = encrypt(file_contents, key)
                    save_file(encrypted_contents, "Encrypted File", "encrypted")
                else:
                    messagebox.showerror("Error", "Invalid key. Please enter a key (1 - 25).")
            elif operation == "decrypt":
                key = tk.simpledialog.askinteger("Decryption Key", "Enter a key (1 - 25):", parent=root, minvalue=1, maxvalue=25)
                if key is not None:
                    decrypted_contents = decrypt(file_contents, key)
                    save_file(decrypted_contents, "Decrypted File", "decrypted")
                else:
                    messagebox.showerror("Error", "Invalid key. Please enter a key (1 - 25).")
            elif operation == "decode":
                decoded_messages = decode(file_contents)
                decoded_message_str = "\n".join(decoded_messages)
                save_file(decoded_message_str, "Decoded File", "decoded")
            else:
                messagebox.showerror("Error", "Invalid operation. Please choose Encrypt, Decrypt, or Decode.")

# Function to save the processed contents to a file
def save_file(contents, title, default_name):
    file_path = filedialog.asksaveasfilename(title=title, defaultextension=".txt", initialfile=f"{default_name}_file.txt")
    if file_path:
        with open(file_path, 'w') as file:
            file.write(contents)
        messagebox.showinfo("Success", f"{title} saved successfully.")

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

# Create buttons for encryption, decryption, decoding, random key generation, and file processing
button_encrypt = tk.Button(root, text="Encrypt", command=on_encrypt, bg="light gray", font=("Garamond", 14), relief=tk.RIDGE)
button_encrypt.grid(row=2, column=0, padx=5, pady=5)

button_decrypt = tk.Button(root, text="Decrypt", command=on_decrypt, bg="light gray", font=("Garamond", 14), relief=tk.RIDGE)
button_decrypt.grid(row=2, column=1, padx=5, pady=5)

button_decode = tk.Button(root, text="Decode", command=on_decode, bg="light gray", font=("Garamond", 14), relief=tk.RIDGE)
button_decode.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

button_generate = tk.Button(root, text="Generate Random Code", command=generate_random_code, bg="light gray", font=("Garamond", 14), relief=tk.RIDGE)
button_generate.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

button_process_file = tk.Button(root, text="Process File", command=process_file, bg="light gray", font=("Garamond", 14), relief=tk.RIDGE)
button_process_file.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

# Start the main event loop
root.mainloop()
