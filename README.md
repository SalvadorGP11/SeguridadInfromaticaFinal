# Proyecto de Comunicación Segura con Steganografía y RSA

Este proyecto consta de dos scripts, `Cliente.py` y `Server.py`, que permiten enviar y recibir mensajes ocultos utilizando técnicas de esteganografía y cifrado RSA.

## Requisitos

### Cliente.py (Máquina 1)

El script `Cliente.py` se utiliza para enviar el mensaje oculto.

#### Instalación de dependencias

1. **Python y pip**
    ```bash
    sudo apt install python3 python3-pip
    ```

2. **Bibliotecas necesarias**
    ```bash
    pip3 install rsa stegano
    sudo apt install python3-tk
    pip3 install pillow
    ```

#### Ejecución

```bash
python3 cliente.py
```

**Nota**
En ocasiones, es necesario crear un entorno virtual para instalar algunas dependencias. Para crear y activar un entorno virtual, sigue estos pasos:

Instalar el paquete completo de Python (incluye venv)
```bash
sudo apt install python3-full
```
Crear y activar el entorno virtual
```bash
python3 -m venv nombre_del_entorno
source nombre_del_entorno/bin/activate
```
Instalar las dependencias dentro del entorno virtual


### Server.py (Máquina 2)
El script `Server.py` se utiliza para recibir el mensaje y realizar el proceso inverso para extraer y desencriptar el mensaje.

1. **Python y pip**
    ```bash
    sudo apt install python3 python3-pip
    ```

2. **Bibliotecas necesarias**
    ```bash
    pip3 install rsa stegano
    pip3 install pillow
    ```

#### Ejecución

```bash
python3 server.py
```
