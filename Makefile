# Makefile for Stockholm project

# Variables
KEY = "^D%YTDC*&Ê*BLJ*&"
PROGRAM = stockholm.py
PYTHON = python

all: rules

encrypt:
	@$(PYTHON) $(PROGRAM) -p $(KEY)

encrypt_silently:
	@$(PYTHON) $(PROGRAM) -p $(KEY) -s

decrypt:
	@$(PYTHON) $(PROGRAM) -r $(KEY)

decrypt_silently:
	@$(PYTHON) $(PROGRAM) -r $(KEY) -s

version:
	@$(PYTHON) $(PROGRAM) -v

help:
	@$(PYTHON) $(PROGRAM) -h

setup:
	mkdir -p $(HOME)/infection/
	cp -r ./infection/* $(HOME)/infection/ 2>/dev/null
	chmod +x $(PROGRAM)
	bash -c "python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"



# Help
rules:
	@echo "Stockholm Makefile"
	@echo "Available targets:"
	@echo "  all					Show this help message"
	@echo "  setup  				setup the projects env"
	@echo "  encrypt          		Run the program to encrypt the content of infection folder"
	@echo "  encrypt_silently		Run the program to encrypt the content of infection folder in silent mode"
	@echo "  decrypt          		Run the program to decrypt the content of infection folder"
	@echo "  decrypt_silently		Run the program to decrypt the content of infection folder in silent mode"
	@echo "  version        		Show the version of the program"
	@echo "  help         			Show this help message"

.PHONY: all setup encrypt encrypt_silently decrypt decrypt_silently version help

