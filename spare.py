import tkinter as tk
from tkinter import messagebox
import pyperclip

def encrypt(message, key):
    """Encrypt message with key."""
    result = ''

    for letter in message:
        if letter.isalpha():
            num = ord(letter)

            if letter.isupper():
                base = ord('A')
            else:
                assert letter.islower()
                base = ord('a')

            num = (num - base + key) % 26 + base

            result += chr(num)
        elif letter.isdigit():
            result += letter
        else:
            result += letter

    return result


def decrypt(message, key):
    """Decrypt message with key."""
    return encrypt(message, -key)


def decode(message):
    """Decode message without key."""
    decoded_messages = []
    for key in range(26):
        decoded_message = decrypt(message, key)
        decoded_messages.append(decoded_message)
    return decoded_messages[:10]  # Return only the first 10 decoded messages


def on_encrypt():
    phrase = entry_message.get()
    key = entry_key.get()
    if phrase.strip() == '' or not key.isdigit() or int(key) < 1 or int(key) > 25:
        messagebox.showerror("Error", "Invalid input. Please enter a message and a key (1 - 25).")
        return
    encrypted_message = encrypt(phrase, int(key))
    pyperclip.copy(encrypted_message)
    messagebox.showinfo("Encrypted Message", "Message copied to clipboard:\n\n" + encrypted_message)
    entry_message.delete(0, tk.END)
    entry_key.delete(0, tk.END)


def on_decrypt():
    phrase = entry_message.get()
    key = entry_key.get()
    if phrase.strip() == '' or not key.isdigit() or int(key) < 1 or int(key) > 25:
        messagebox.showerror("Error", "Invalid input. Please enter a message and a key (1 - 25).")
        return
    decrypted_message = decrypt(phrase, int(key))
    pyperclip.copy(decrypted_message)
    messagebox.showinfo("Decrypted Message", "Message copied to clipboard:\n\n" + decrypted_message)
    entry_message.delete(0, tk.END)
    entry_key.delete(0, tk.END)


def on_decode():
    phrase = entry_message.get()
    if phrase.strip() == '':
        messagebox.showerror("Error", "Invalid input. Please enter a message.")
        return
    decoded_messages = decode(phrase)
    decoded_message_str = "\n\n".join(decoded_messages)
    pyperclip.copy(decoded_message_str)
    messagebox.showinfo("Decoded Messages", "First 10 possible decoded messages copied to clipboard:\n\n" + decoded_message_str)
    entry_message.delete(0, tk.END)


root = tk.Tk()
root.title("Message Encryption")
root.configure(bg="beige") 

label_message = tk.Label(root, text="Message:")
label_message.grid(row=0, column=0, padx=5, pady=5)
entry_message = tk.Entry(root)
entry_message.grid(row=0, column=1, padx=5, pady=5)

label_key = tk.Label(root, text="Key (1 - 25):")
label_key.grid(row=1, column=0, padx=5, pady=5)
entry_key = tk.Entry(root)
entry_key.grid(row=1, column=1, padx=5, pady=5)

button_encrypt = tk.Button(root, text="Encrypt", command=on_encrypt, bg="green",fg="white")
button_encrypt.grid(row=2, column=0, padx=5, pady=5)


button_decrypt = tk.Button(root, text="Decrypt", command=on_decrypt, bg="red", fg="white")
button_decrypt.grid(row=2, column=1, padx=5, pady=5)



button_decode = tk.Button(root, text="Decode", command=on_decode, bg="orange",fg="black")
button_decode.grid(row=3, column=0, columnspan=2, padx=5, pady=5)


root.mainloop()


