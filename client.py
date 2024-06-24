import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog
import threading
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import hashlib

def create_aes_cipher(aes_key, aes_iv):
    return AES.new(aes_key, AES.MODE_CBC, aes_iv)

# Load the server's public RSA key
with open('my_rsa.pub', 'rb') as f:
    public_key = RSA.import_key(f.read())

def receive_key_iv(sock):
    key_iv = sock.recv(32)
    aes_key = key_iv[:16]
    aes_iv = key_iv[16:]
    return aes_key, aes_iv

def encrypt_message(aes_key, aes_iv, message):
    cipher = create_aes_cipher(aes_key, aes_iv)
    return cipher.iv + cipher.encrypt(pad(message.encode(), AES.block_size))

def decrypt_message(aes_key, aes_iv, encrypted_message):
    iv = encrypted_message[:16]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted_message[16:]), AES.block_size).decode()
    return decrypted

def receive_messages(sock, message_list, aes_key, aes_iv):
    while True:
        data = sock.recv(4096)
        if not data:
            print("\nDisconnected from server.")
            break
        if data.startswith(b'OFFERFILE:'):
            filename, filesize = data.split(b':')[1:]
            should_download = messagebox.askyesno("Download File", f"Do you want to download {filename.decode()} of size {filesize.decode()} bytes?")
            if should_download:
                sock.sendall(b'ACCEPTFILE:' + filename)
        elif data.startswith(b'FILE:'):
            _, filename, filesize, content = data.split(b':', 3)
            save_downloaded_file(filename.decode(), content)
            message_list.insert(tk.END, f"{filename.decode()} downloaded successfully.")
        else:
            message = decrypt_message(aes_key, aes_iv, bytes.fromhex(data[4:].decode()))
            message_list.insert(tk.END, "Received: " + message)

def send_message(entry_field, client, aes_key, aes_iv):
    user_input = entry_field.get()
    encrypted_message = encrypt_message(aes_key, aes_iv, user_input)
    client.sendall(b'MSG:' + encrypted_message.hex().encode())
    entry_field.delete(0, tk.END)

def send_file(client, aes_key, aes_iv):
    filepath = filedialog.askopenfilename()
    if filepath:
        with open(filepath, 'rb') as file:
            file_content = file.read()
        if len(file_content) > 50 * 1024 * 1024:
            messagebox.showwarning("File Size Limit", "The file size exceeds the 50 MB limit.")
            return
        filename = os.path.basename(filepath)
        filesize = str(len(file_content))
        client.sendall(b'FILE:' + filename.encode() + b':' + filesize.encode() + b':' + file_content)

def save_downloaded_file(filename, content):
    file_path = os.path.join("downloaded_files", filename)
    os.makedirs("downloaded_files", exist_ok=True)
    with open(file_path, 'wb') as file:
        file.write(content)

def setup_gui(client, aes_key, aes_iv):
    root = tk.Tk()
    root.title("Client")

    messages_frame = tk.Frame(root)
    scrollbar = tk.Scrollbar(messages_frame)
    message_list = tk.Listbox(messages_frame, height=15, width=50, yscrollcommand=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    message_list.pack(side=tk.LEFT, fill=tk.BOTH)
    message_list.pack()
    messages_frame.pack()

    entry_field = tk.Entry(root, textvariable=tk.StringVar())
    entry_field.bind("<Return>", lambda event: send_message(entry_field, client, aes_key, aes_iv))
    entry_field.pack()
    send_button = tk.Button(root, text="Send", command=lambda: send_message(entry_field, client, aes_key, aes_iv))
    send_button.pack()

    send_file_button = tk.Button(root, text="Send File", command=lambda: send_file(client, aes_key, aes_iv))
    send_file_button.pack()

    thread_receive = threading.Thread(target=receive_messages, args=(client, message_list, aes_key, aes_iv), daemon=True)
    thread_receive.start()

    root.mainloop()

def main():
    HOST = ''
    PORT = 
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    aes_key, aes_iv = receive_key_iv(client)
    print("Connected to the server and received key and IV.")
    setup_gui(client, aes_key, aes_iv)

if __name__ == "__main__":
    main()
