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

# Función para solicitar la llave pública al servidor
def get_public_key(server_ip):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_ip, 12345))
        s.sendall(b'GET_KEY')
        public_key_data = s.recv(4096)
    public_key = rsa.PublicKey.load_pkcs1(public_key_data)
    return public_key

# Función para capturar un mensaje o elegir un archivo
def get_message():
    choice = input("¿Quieres capturar un mensaje (1) o elegir un archivo (2)? ")
    if choice == '1':
        return input("Ingresa el mensaje: ").encode()
    elif choice == '2':
        Tk().withdraw()  # Ocultar la ventana principal de Tkinter
        file_path = askopenfilename(title="Selecciona un archivo")
        if not file_path:
            print("No se seleccionó ningún archivo. Saliendo...")
            sys.exit(1)
        with open(file_path, 'rb') as file:
            return file.read()
    else:
        print("Opción no válida.")
        sys.exit(1)

# Función para generar hashes
def generate_hash(data, hash_type):
    hash_func = hashlib.new(hash_type)
    hash_func.update(data)
    return hash_func.hexdigest()

# Función para encriptar el mensaje con RSA inverso
def encrypt_message_rsa(message, public_key):
    encrypted_chunks = []
    chunk_size = (public_key.n.bit_length() + 7) // 8 - 11
    for i in range(0, len(message), chunk_size):
        chunk = message[i:i + chunk_size]
        encrypted_chunks.append(rsa.encrypt(chunk, public_key))
    return b''.join(encrypted_chunks)

# Función para esconder el mensaje en un objeto
def hide_message(message):
    Tk().withdraw()  # Ocultar la ventana principal de Tkinter
    image_path = askopenfilename(title="Selecciona una imagen para esconder el mensaje")
    if not image_path:
        print("No se seleccionó ninguna imagen. Saliendo...")
        sys.exit(1)
    secret_image = lsb.hide(image_path, message.decode('latin-1'))  # Usar latin-1 para evitar problemas de codificación
    secret_image_path = "secret_image.png"
    secret_image.save(secret_image_path)
    return secret_image_path

# Función para enviar datos grandes
def send_large_data(sock, data):
    data_size = len(data)
    print(f"Enviando tamaño de datos: {data_size} bytes")
    sock.sendall(data_size.to_bytes(8, byteorder='big'))
    for i in range(0, data_size, 4096):
        sock.sendall(data[i:i + 4096])
    print("Datos enviados completamente")

# Solicitar la IP del servidor al usuario
server_ip = input("Ingresa la IP del servidor: ")

# Obtener y mostrar la MAC address del equipo cliente en decimal
client_mac = get_mac()
print(f"MAC Address del cliente: {client_mac}")
#formatted_mac = ':'.join(('%012X' % client_mac)[i:i+2] for i in range(0, 12, 2))
#print(f"MAC Address del cliente: {formatted_mac}")

# Obtener la llave pública del servidor
public_key = get_public_key(server_ip)
print(f"Llave pública obtenida")

# Capturar el mensaje o archivo
message = get_message()

# Generar el hash SHA-384 del mensaje
hash_sha384 = generate_hash(message, 'sha384')
print(f"HASH SHA-384 del mensaje: {hash_sha384}")

# Encriptar el mensaje con RSA inverso
encrypted_message = encrypt_message_rsa(message, public_key)

# Generar el hash SHA-512 del mensaje encriptado
hash_sha512 = generate_hash(encrypted_message, 'sha512')
print(f"HASH SHA-512 del mensaje encriptado: {hash_sha512}")

# Esconder el mensaje en una imagen
secret_image_path = hide_message(encrypted_message)

# Generar el hash Blake2 del mensaje escondido
with open(secret_image_path, 'rb') as secret_image_file:
    secret_image_data = secret_image_file.read()
hash_blake2 = generate_hash(secret_image_data, 'blake2b')
print(f"HASH Blake2 del mensaje escondido: {hash_blake2}")

# Enviar el mensaje al servidor
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_ip, 12345))
        s.sendall(b'SEND_MESSAGE')
        s.sendall(hash_sha384.encode())
        s.sendall(hash_sha512.encode())
        s.sendall(hash_blake2.encode())
        send_large_data(s, secret_image_data)
    print("Mensaje enviado al servidor.")
except ConnectionResetError as e:
    print(f"Error: Conexión reiniciada por el servidor: {e}")
except Exception as e:
    print(f"Error inesperado: {e}")
