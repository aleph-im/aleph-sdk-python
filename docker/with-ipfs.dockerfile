# Base image for Python 3.10
FROM python:3.10

# Define build argument for the Kubo IPFS version for flexibility and easy updates.
ARG KUBO_VERSION="v0.26.0"
ARG KUBO_ARCH="linux-amd64"

# --- Install System Dependencies and IPFS Client ---
# Combined RUN command to reduce layer count and clean up immediately.
RUN apt-get update && \
    # Install required dependencies: wget for IPFS, libsecp256k1-dev for Aleph-Client
    apt-get install -y --no-install-recommends \
        wget \
        libsecp256k1-dev \
        libffi-dev \
        && \
    # Download and extract Kubo IPFS
    wget https://dist.ipfs.tech/kubo/${KUBO_VERSION}/kubo_${KUBO_VERSION}_${KUBO_ARCH}.tar.gz -O /tmp/kubo.tar.gz && \
    tar -xvzf /tmp/kubo.tar.gz -C /usr/local/bin/ && \
    # Move the executable directly to a PATH directory and remove the temporary folder/tar file
    mv /usr/local/bin/kubo/ipfs /usr/local/bin/ipfs && \
    rm -rf /usr/local/bin/kubo /tmp/kubo.tar.gz && \
    # Clean up APT caches and lists to minimize the final image size
    apt-get purge -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# --- IPFS Configuration ---
# Set the environment variable for the IPFS repository path
ENV IPFS_PATH /var/lib/ipfs

# Create the directory for IPFS data persistence. 
# Must be created by root before switching users.
RUN mkdir -p ${IPFS_PATH}

# Expose necessary IPFS ports
# 4001: Swarm (P2P communication)
EXPOSE 4001
# 5001: API (WebUI/Remote operations)
EXPOSE 5001
# 8080: Gateway (HTTP access to files)
EXPOSE 8080

# --- Aleph-Client Installation ---
# Set up a working directory for the Python project
WORKDIR /opt/aleph-sdk-python/

# Copy project files
COPY . .

# Install the package with the 'testing' extra dependencies.
# Note: Using '-e' (editable mode) is standard for local development 
# but often omitted for production builds in favor of a clean 'pip install .'
RUN pip install -e .[testing]

# --- User Setup and Final Configuration ---
# Create the unprivileged user 'aleph' to run the services for security
RUN useradd --create-home --no-log-init --shell /bin/bash aleph

# Change the ownership of the IPFS data path to the 'aleph' user
RUN chown -R aleph:aleph ${IPFS_PATH}

# Set the primary working directory and switch to the unprivileged user
WORKDIR /home/aleph
USER aleph

# Volume for external persistence (should be defined after user setup if possible, 
# but VOLUME directive is often placed near EXPOSE/ENV)
VOLUME ${IPFS_PATH}

# Copy the entrypoint script and ensure the 'aleph' user can execute it
COPY docker/with-ipfs.entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
# Note: The entrypoint file is copied by root and ownership needs to be checked 
# if the script modifies files outside /home/aleph. Using USER aleph handles execution privileges.

# Command to run when the container starts
CMD ["/entrypoint.sh"]
