# Use a specific, stable version of Python
FROM python:3.10

# --- IPFS (Kubo) Installation ---
# Install necessary tools for downloading
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        wget \
        tar \
    && rm -rf /var/lib/apt/lists/*

# Download, extract, and symlink IPFS (Kubo)
ARG KUBO_VERSION=v0.15.0
RUN wget https://ipfs.io/ipns/dist.ipfs.io/kubo/${KUBO_VERSION}/kubo_${KUBO_VERSION}_linux-amd64.tar.gz && \
    tar -xvzf kubo_${KUBO_VERSION}_linux-amd64.tar.gz -C /opt/ && \
    rm kubo_${KUBO_VERSION}_linux-amd64.tar.gz && \
    ln -s /opt/kubo/ipfs /usr/local/bin/

# Volume and environment for IPFS data persistence
RUN mkdir /var/lib/ipfs
ENV IPFS_PATH /var/lib/ipfs
VOLUME /var/lib/ipfs

# Expose required IPFS ports
EXPOSE 4001 5001 8080


# --- Aleph-Client Installation and Dependencies ---

# Install cryptography dependencies (libsecp256k1-dev)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libsecp256k1-dev \
    && rm -rf /var/lib/apt/lists/*

# Setup working directory and copy source code
RUN mkdir /opt/aleph-sdk-python/
WORKDIR /opt/aleph-sdk-python/
COPY . .

# Install the package in editable mode with testing dependencies
RUN pip install -e .[testing]


# --- Security and Entrypoint Configuration ---

# 1. Create a dedicated, non-root user for running the application
RUN useradd --create-home -s /bin/bash aleph

# 2. **CRITICAL FIX:** Change ownership of the IPFS data directory to the 'aleph' user
RUN chown -R aleph:aleph /var/lib/ipfs

# Set the final working directory to the user's home
WORKDIR /home/aleph

# Set the execution context to the non-root user
USER aleph

# Copy the entrypoint script
COPY docker/with-ipfs.entrypoint.sh /entrypoint.sh

# Define the command to run when the container starts
CMD ["/entrypoint.sh"]
