# STOCKHOLM
## Overview
 - Stockholm is a simulation tool that demonstrates how ransomware like WannaCry targets and encrypts files.
 - It only operates within a designated folder ($HOME/infection) to ensure safety.

## Features
 - Encrypts files with extensions targeted by WannaCry.
 - Adds .ft extension to encrypted files.
 - Decrypts files with the correct key.
 - Command-line options for various functions.

## Requirements
 - Python 3.6 or higher
 - cryptography library

## Installation
Clone this repository:
```bash
git clone ... stockholm
cd stockholm
```

### Build and Run the Docker image:
```bash
docker build -t stockholm .
docker run -it stockholm
```

### Install required dependencies:
```bash
make setup
```
### Activate the virtual env
```bash
source venv/bin/activate
```

### Show all the available Features
```bash
make rules
```

### Options:
```bash
-h, --help: Show help message and exit
-v, --version: Show program version and exit
-r, --reverse KEY: Decrypt files using the provided KEY
-s, --silent: Run without displaying output
-p, --password: Encrypt files using the provided KEY
```