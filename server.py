import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import hashlib
from Crypto.Random import get_random_bytes

aes_key = get_random_bytes(16)
aes_iv = get_random_bytes(16)

def create_aes_cipher(key, iv):
    return AES.new(key, AES.MODE_CBC, iv)

# Load RSA private key
with open('my_rsa', 'rb') as f:
    private_key = RSA.import_key(f.read())
clients = []

def create_aes_cipher():
    return AES.new(aes_key, AES.MODE_CBC, aes_iv)

def send_key_iv(client_socket):
    client_socket.send(aes_key + aes_iv)

def encrypt_message(message):
    cipher = create_aes_cipher()
    return cipher.iv + cipher.encrypt(pad(message.encode(), AES.block_size))

def decrypt_message(encrypted_message):
    iv = encrypted_message[:16]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_message[16:]), AES.block_size).decode()

def broadcast(message, sender=None):
    for client in clients:
        if client != sender:
            try:
                client.sendall(message)
            except:
                clients.remove(client)

def handle_client(conn, addr):
    clients.append(conn)
    send_key_iv(conn)
    print(f"New connection from {addr}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                raise ConnectionError("Connection lost from " + str(addr))

            if data.startswith(b'FILE:'):
                _, filename, filesize, content = data.split(b':', 3)
                file_path = os.path.join("server_files", filename.decode())
                os.makedirs("server_files", exist_ok=True)
                with open(file_path, 'wb') as file:
                    file.write(content)
                print(f"Received file {filename.decode()} of size {filesize.decode()}")
                broadcast(b'OFFERFILE:' + filename + b':' + filesize, conn)
            elif data.startswith(b'ACCEPTFILE:'):
                filename = data.split(b':')[1].decode()
                send_file_to_clients(filename, conn, addr)
            elif data.startswith(b'MSG:'):
                message = decrypt_message(bytes.fromhex(data[4:].decode()))
                print(f"Received from {addr}: {message}")
                broadcast(data, conn)
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        conn.close()
        clients.remove(conn)
        print(f"Connection closed with {addr}")

def send_file_to_clients(filename, conn, addr):
    file_path = os.path.join("server_files", filename)
    if os.path.isfile(file_path):
        with open(file_path, 'rb') as file:
            content = file.read()
            filesize = str(len(content))
            conn.sendall(b'FILE:' + filename.encode() + b':' + filesize.encode() + b':' + content)
            print(f"File {filename} downloaded successfully by {addr}")

def main():
    HOST = ''
    PORT = 
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print("Server is running...")
    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()
    finally:
        server.close()

if __name__ == "__main__":
    main()
