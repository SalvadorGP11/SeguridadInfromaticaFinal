import socket
import rsa
import hashlib
import os
import sys
from uuid import getnode as get_mac
from stegano import lsb
from pathlib import Path
from tkinter import Tk
from tkinter.filedialog import askopenfilename

#(A)
def get_public_key_and_mac(server_ip):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_ip, 12345))
        s.sendall(b'GET_KEY')
        response = s.recv(4096).decode().split('\n')
        server_mac = int(response[0])
        public_key_data = '\n'.join(response[1:]).encode()
    public_key = rsa.PublicKey.load_pkcs1(public_key_data)
    return public_key, server_mac

#(B)
def get_message():
    choice = input("¿Quieres capturar un mensaje (1) o elegir un archivo (2)? ")
    if choice == '1':
        return input("Ingresa el mensaje: ").encode()
    elif choice == '2':
        root = Tk()
        root.withdraw()  # Ocultar la ventana principal de Tkinter
        file_path = askopenfilename(title="Selecciona un archivo")
        with open(file_path, 'rb') as file:
            return file.read()
    else:
        print("Opción no válida.")
        sys.exit(1)

#(C)
def generate_hash(data, hash_type):
    hash_func = hashlib.new(hash_type)
    hash_func.update(data)
    return hash_func.hexdigest()

#(D)
def encrypt_message_rsa(message, public_key):
    encrypted_chunks = []
    chunk_size = (public_key.n.bit_length() + 7) // 8 - 11
    for i in range(0, len(message), chunk_size):
        chunk = message[i:i + chunk_size]
        encrypted_chunks.append(rsa.encrypt(chunk, public_key))
    return b''.join(encrypted_chunks)

#(E)
def hide_message(message):
    root = Tk()
    root.withdraw()  
    image_path = askopenfilename(title="Selecciona una imagen para esconder el mensaje")
    secret_image = lsb.hide(image_path, message.decode('latin-1'))  
    secret_image_path = "secret_image.png"
    secret_image.save(secret_image_path)
    return secret_image_path

#(F)
def send_large_data(sock, data):
    data_size = len(data)
    sock.sendall(data_size.to_bytes(8, byteorder='big'))
    for i in range(0, data_size, 4096):
        sock.sendall(data[i:i + 4096])

#(G)
server_ip = input("Ingresa la IP del servidor: ")

#
public_key, server_mac = get_public_key_and_mac(server_ip)
formatted_mac = ':'.join(('%012X' % server_mac)[i:i+2] for i in range(0, 12, 2))
print(f"MAC Address del servidor: {formatted_mac}")
print(f"Llave pública obtenida: {public_key}")

# Obtener y mostrar la MAC address del equipo cliente
#client_mac = get_mac()
#formatted_client_mac = ':'.join(('%012X' % client_mac)[i:i+2] for i in range(0, 12, 2))
#print(f"MAC Address del cliente: {formatted_client_mac}")

#(H)
message = get_message()

#(I)
hash_sha384 = generate_hash(message, 'sha384')
print(f"Hash SHA-384 del mensaje: {hash_sha384}")

#(J)
encrypted_message = encrypt_message_rsa(message, public_key)

#(K)
hash_sha512 = generate_hash(encrypted_message, 'sha512')
print(f"Hash SHA-512 del mensaje encriptado: {hash_sha512}")

#(L)
secret_image_path = hide_message(encrypted_message)

#(M)
with open(secret_image_path, 'rb') as secret_image_file:
    secret_image_data = secret_image_file.read()
hash_blake2 = generate_hash(secret_image_data, 'blake2b')
print(f"Hash Blake2 del mensaje escondido: {hash_blake2}")

#(N)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((server_ip, 12345))
    s.sendall(b'SEND_MESSAGE')
    s.sendall(hash_sha384.encode())
    s.sendall(hash_sha512.encode())
    s.sendall(hash_blake2.encode())
    send_large_data(s, secret_image_data)

print("Mensaje enviado al servidor.")
