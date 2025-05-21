import os
import sys
import argparse
import base64
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Constants
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # AES-256
ITERATIONS = 100_000


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from the password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_file(filepath: str, password: str):
    with open(filepath, 'rb') as f:
        plaintext = f.read()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    encrypted = salt + nonce + ciphertext
    with open(filepath + '.enc', 'wb') as f:
        f.write(encrypted)

    print(f'[+] File encrypted: {filepath}.enc')


def decrypt_file(filepath: str, password: str):
    with open(filepath, 'rb') as f:
        data = f.read()

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        print('[!] Decryption failed. Possibly incorrect password.')
        sys.exit(1)

    output_path = filepath.replace('.enc', '.dec')
    with open(output_path, 'wb') as f:
        f.write(plaintext)

    print(f'[+] File decrypted: {output_path}')


def main():
    parser = argparse.ArgumentParser(description="AES-256 File Encryptor")
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help="Mode: encrypt or decrypt")
    parser.add_argument('file', help="Path to the input file")

    args = parser.parse_args()
    password = getpass.getpass(prompt="Enter password: ")

    if args.mode == 'encrypt':
        encrypt_file(args.file, password)
    else:
        decrypt_file(args.file, password)


if __name__ == '__main__':
    main()
