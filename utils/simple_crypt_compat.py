import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def logs(message):
    global silentMode

    if not silentMode:
        print(message)

def derive_key(password, salt):
    # Generate a key from the 16-character password usingPBKDF2HMAC with SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 requires 32 bytes
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    #generate a 16-byte salt && iv
    salt = os.urandom(16)
    iv = os.urandom(16)

    key = derive_key(password, salt)

     # Read the file's content
    with open(file_path, 'rb') as f:
        file_data = f.read()

     # Apply padding to the file data (AES requires data to be a multiple of block size)
    padder = padding.PKCS7(128).padder()  # 128 bits = 16 bytes block size
    padded_data = padder.update(file_data) + padder.finalize()

    # Initialize AES CBC cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Write the encrypted data to a new file
    encrypted_file_path = str(file_path) + '.ft'
    with open(encrypted_file_path, 'wb') as f:
        # Write the salt, IV, and encrypted data to the file
        f.write(salt + iv + encrypted_data)

    os.remove(file_path)

def decrypt_file(file_path, password):
    # Read the encrypted file
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    # Extract salt, IV, and encrypted data from the file
    salt = file_data[:16]
    iv = file_data[16:32]
    encrypted_data = file_data[32:]

    # Derive the AES key from the password and salt
    key = derive_key(password, salt)

    # Initialize AES CBC cipher for decryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Write the decrypted data to a new file
    decrypted_file_path = file_path.with_suffix('')
    with open(decrypted_file_path, 'wb') as f:
        f.write(unpadded_data)

    os.remove(file_path)