import socket
import rsa
import hashlib
from stegano import lsb
from pathlib import Path
from uuid import getnode as get_mac

# (A)
(public_key, private_key) = rsa.newkeys(2048)

# (B)
def extract_message(image_path):
    return lsb.reveal(image_path).encode('latin-1')  # Usar latin-1 para decodificar correctamente

# (C)
def receive_large_data(conn):
    data_size = int.from_bytes(conn.recv(8), byteorder='big')
    print(f"Esperando recibir {data_size} bytes de datos")
    received_data = b''
    while len(received_data) < data_size:
        packet = conn.recv(4096)
        if not packet:
            break
        received_data += packet
    print("Datos recibidos completamente")
    return received_data

# (D)
def generate_hash(data, hash_type):
    hash_func = hashlib.new(hash_type)
    hash_func.update(data)
    return hash_func.hexdigest()

# (E)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(('0.0.0.0', 12345))
    s.listen(1)
    print("Servidor escuchando en el puerto 12345...")
    while True:
        conn, addr = s.accept()
        with conn:
            print(f"Conexión establecida con {addr}")
            data = conn.recv(1024)
            if data == b'GET_KEY':
                server_mac = get_mac()
                conn.sendall(f"{server_mac}".encode() + b'\n' + public_key.save_pkcs1())
            elif data == b'SEND_MESSAGE':
                try:
                    hash_sha384 = conn.recv(96).decode()
                    hash_sha512 = conn.recv(128).decode()
                    hash_blake2 = conn.recv(128).decode()
                    secret_image_data = receive_large_data(conn)
                    if len(secret_image_data) != 0:  # 
                        with open("received_secret_image.png", 'wb') as file:
                            file.write(secret_image_data)

                        # (F)
                        calculated_blake2 = generate_hash(secret_image_data, 'blake2b')
                        print(f"Hash Blake2 recibido: {hash_blake2}")
                        print(f"Hash Blake2 calculado: {calculated_blake2}")
                        if calculated_blake2 != hash_blake2:
                            print("Comunicación alterada: hash Blake2 no coincide. Eliminando mensaje.")
                            Path("received_secret_image.png").unlink()
                            continue

                        # (G)
                        extracted_message = extract_message("received_secret_image.png")
                        print(f"Mensaje extraído: {extracted_message}")

                        # (H)
                        calculated_sha512 = generate_hash(extracted_message, 'sha512')
                        print(f"Hash SHA-512 recibido: {hash_sha512}")
                        print(f"Hash SHA-512 calculado: {calculated_sha512}")
                        if calculated_sha512 != hash_sha512:
                            print("Error: hash SHA-512 no coincide. Eliminando mensaje.")
                            Path("received_secret_image.png").unlink()
                            continue

                        # (I)
                        try:
                            decrypted_message = rsa.decrypt(extracted_message, private_key)
                            print(f"Mensaje desencriptado: {decrypted_message}")
                        except Exception as decryption_error:
                            print(f"Error de desencriptación: {decryption_error}")
                            Path("received_secret_image.png").unlink()
                            continue
                            
             

                        # (J)
                        calculated_sha384 = generate_hash(decrypted_message, 'sha384')
                        print(f"Hash SHA-384 recibido: {hash_sha384}")
                        print(f"Hash SHA-384 calculado: {calculated_sha384}")
                        if calculated_sha384 != hash_sha384:
                            print("Sistema vulnerado: hash SHA-384 no coincide. Eliminando mensaje.")
                            Path("received_secret_image.png").unlink()
                            continue

                        #
                        print("Mensaje verificado y listo.")

                        # (K)
                        try:
                            Path("received_secret_image.png").unlink()
                            print("Objeto encubridor eliminado.")
                        except FileNotFoundError:
                            print("El objeto encubridor ya había sido eliminado.")
                    else:
                        print("Error: No se recibió el dato completo.")
                except Exception as e:
                    print(f"Error durante la recepción del mensaje: {e}")
                    continue  #
