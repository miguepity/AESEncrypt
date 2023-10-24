from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import urlsafe_b64encode, urlsafe_b64decode


def encrypt(plain_text, key):
    # Convertir la clave y el texto en claro en bytes
    key_bytes = key.encode('utf-8')
    plain_text_bytes = plain_text.encode('utf-8')

    # Aplicar padding al texto en claro
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plain_text_bytes) + padder.finalize()

    # Configurar el algoritmo de cifrado AES con la clave
    cipher = Cipher(algorithms.AES(key_bytes),
                    modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encriptar los datos
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()

    # Codificar el texto cifrado en base64 para facilitar la representación
    encoded_cipher_text = urlsafe_b64encode(cipher_text).decode('utf-8')

    return encoded_cipher_text


def decrypt(encoded_cipher_text, key):
    # Convertir la clave y el texto cifrado en bytes
    key_bytes = key.encode('utf-8')
    cipher_text = urlsafe_b64decode(encoded_cipher_text.encode('utf-8'))

    # Configurar el algoritmo de cifrado AES con la clave
    cipher = Cipher(algorithms.AES(key_bytes),
                    modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    # Descifrar los datos
    decrypted_data = decryptor.update(cipher_text) + decryptor.finalize()

    # Quitar el padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plain_text_bytes = unpadder.update(decrypted_data) + unpadder.finalize()

    # Decodificar el texto en claro de bytes a cadena
    plain_text = plain_text_bytes.decode('utf-8')

    return plain_text


# Ejemplo de uso
mensaje_original = "Hola, este es un mensaje secreto."

# Algoritmo AES solo permite valores 128, 192, 256 bit como longitud de la llave
# lo que representa 16, 24, o 32 bytes
# Por lo que la clave debe de tener 16, 24, o 32 caracteres
clave_compartida = "clave_secreta_prueba_dem"

# Encriptar el mensaje
texto_cifrado = encrypt(mensaje_original, clave_compartida)
print("Texto Cifrado:", texto_cifrado)

# Descifrar el mensaje
mensaje_descifrado = decrypt(texto_cifrado, clave_compartida)
print("Mensaje Descifrado:", mensaje_descifrado)
