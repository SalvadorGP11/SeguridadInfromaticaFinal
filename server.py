import socket
import rsa
import hashlib
from stegano import lsb
from pathlib import Path

# Generar llaves RSA
(public_key, private_key) = rsa.newkeys(2048)

# Función para extraer el mensaje escondido
def extract_message(image_path):
    return lsb.reveal(image_path).encode('latin-1')  # Usar latin-1 para decodificar correctamente

# Función para recibir datos grandes
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

# Crear el socket del servidor
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
                conn.sendall(public_key.save_pkcs1())
            elif data == b'SEND_MESSAGE':
                try:
                    hash_sha384 = conn.recv(96).decode()
                    hash_sha512 = conn.recv(128).decode()
                    hash_blake2 = conn.recv(128).decode()
                    secret_image_data = receive_large_data(conn)
                    if len(secret_image_data) != 0:  # Verificación adicional para asegurarse de que se recibió el dato
                        with open("received_secret_image.png", 'wb') as file:
                            file.write(secret_image_data)

                        # Extraer el mensaje
                        extracted_message = extract_message("received_secret_image.png")
                        print(f"Mensaje extraído: {extracted_message}")

                        # Eliminar el objeto encubridor
                        steg_object_path = Path("received_secret_image.png")
                        steg_object_path.unlink()
                        print(f"Stegobjeto eliminado: {steg_object_path}")

                        # Desencriptar el mensaje con la llave privada
                        try:
                            decrypted_message = rsa.decrypt(extracted_message, private_key)
                            print(f"Mensaje desencriptado: {decrypted_message}")
                        except Exception as decryption_error:
                            print(f"Error de desencriptación: {decryption_error}")
                            continue

                        print(f"Hash SHA-384 recibido: {hash_sha384}")
                        print(f"Hash SHA-512 recibido: {hash_sha512}")
                        print(f"Hash Blake2 recibido: {hash_blake2}")

                        # Eliminar el objeto encubridor después de extraer y desencriptar el mensaje
                        try:
                            Path("received_secret_image.png").unlink()
                            print("Objeto encubridor eliminado.")
                        except FileNotFoundError:
                            print("El objeto encubridor ya había sido eliminado.")
                    else:
                        print("Error: No se recibió el dato completo.")
                except Exception as e:
                    print(f"Error durante la recepción del mensaje: {e}")
                    continue  # Asegurar que el servidor siga escuchando nuevas conexiones
