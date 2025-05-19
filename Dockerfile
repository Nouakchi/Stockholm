FROM ubuntu:22.04

# Install Python and pip
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv 

WORKDIR /lab

COPY . .

ENTRYPOINT ["/bin/bash"]