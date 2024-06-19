from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import b64encode, b64decode
import os
import argparse

# Função para gerar chave a partir de senha
def generate_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Função para encriptar dados
def encrypt_data(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return iv + encrypted_data

# Função para desencriptar dados
def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data

# Função para encriptar texto
def encrypt_text(text, password):
    salt = os.urandom(16)
    key = generate_key_from_password(password, salt)
    encrypted_data = encrypt_data(text.encode(), key)
    return b64encode(salt + encrypted_data).decode()

# Função para desencriptar texto
def decrypt_text(encrypted_text, password):
    encrypted_data = b64decode(encrypted_text)
    salt = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    key = generate_key_from_password(password, salt)
    decrypted_data = decrypt_data(encrypted_data, key)
    return decrypted_data.decode()

# Função para encriptar arquivo
def encrypt_file(file_path, password):
    salt = os.urandom(16)
    key = generate_key_from_password(password, salt)
    
    with open(file_path, 'rb') as f:
        file_data = f.read()

    encrypted_data = encrypt_data(file_data, key)

    with open(file_path + ".enc", 'wb') as f:
        f.write(salt + encrypted_data)

# Função para desencriptar arquivo
def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    salt = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    key = generate_key_from_password(password, salt)

    decrypted_data = decrypt_data(encrypted_data, key)

    output_path = file_path.replace(".enc", "")
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)

# Função principal para a interface de linha de comando
def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt text and files.")
    parser.add_argument("mode", choices=["encrypt-text", "decrypt-text", "encrypt-file", "decrypt-file"], help="Mode of operation")
    parser.add_argument("input", help="Input text or file path")
    parser.add_argument("password", help="Password for encryption/decryption")
    
    args = parser.parse_args()
    
    if args.mode == "encrypt-text":
        encrypted_text = encrypt_text(args.input, args.password)
        print(f"Encrypted text: {encrypted_text}")
    elif args.mode == "decrypt-text":
        decrypted_text = decrypt_text(args.input, args.password)
        print(f"Decrypted text: {decrypted_text}")
    elif args.mode == "encrypt-file":
        encrypt_file(args.input, args.password)
        print(f"File encrypted: {args.input}.enc")
    elif args.mode == "decrypt-file":
        decrypt_file(args.input, args.password)
        print(f"File decrypted: {args.input.replace('.enc', '')}")

# Exemplo de uso
if __name__ == "__main__":
    main()
