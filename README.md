
Overview
Stockholm is a simulation tool that demonstrates how ransomware like WannaCry targets and encrypts files.
It only operates within a designated folder ($HOME/infection) to ensure safety.
IMPORTANT: This program is for educational purposes only. DO NOT use it maliciously.
Features

Encrypts files with extensions targeted by WannaCry
Adds .ft extension to encrypted files
Decrypts files with the correct key
Secure encryption using AES-256-GCM
Command-line options for various functions

Requirements

Python 3.6 or higher
cryptography library

Installation

Clone this repository:
```bash
git clone https://github.com/yourusername/stockholm.git
cd stockholm
```

Install dependencies:
```bash
pip install -r requirements.txt
```

Make the script executable:
```bash
chmod +x stockholm.py
```

Usage
Basic usage:

```bash
./stockholm.py [options]
```

Options:

-h, --help: Show help message and exit
-v, --version: Show program version and exit
-r, --reverse KEY: Decrypt files using the provided KEY
-s, --silent: Run without displaying output

Examples:

Encrypt files in the infection folder:
```bash
./stockholm.py
```

Encrypt files without showing output:
```bash
./stockholm.py --silent
```

ecrypt files using a key:
```bash
./stockholm.py --reverse YOUR_ENCRYPTION_KEY
```

Show program version:
```bash
./stockholm.py --version
```

How It Works

The program only operates on files in the $HOME/infection directory
It targets files with extensions that were affected by WannaCry
Files are encrypted using AES-256-GCM with a secure key
Encrypted files are renamed with an additional .ft extension
The decryption process restores files to their original state when provided with the correct key

Safety Features

Only operates in the designated infection folder
Will not encrypt already encrypted files
Generates and displays a secure key for later decryption