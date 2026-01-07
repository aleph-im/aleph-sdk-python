#!/bin/sh

# Exit immediately if a command exits with a non-zero status (-e).
# Treat unset variables as an error (-u).
# Disable globbing (-f) for robust parsing (though often omitted).
set -euf

# Define constants for the image name and build paths
PYTHON_IMAGE_TAG="aleph-sdk-python"
DOCKERFILE_PATH="docker/python-3.9.dockerfile"
DIST_DIR="./dist"

# --- Container Engine Detection ---

# Check if Podman is installed and executable. Prioritize Podman over Docker.
if hash podman 2> /dev/null; then
  CONTAINER_CMD=podman
else
  # Fall back to the default Docker command if Podman is not found.
  CONTAINER_CMD=docker
fi

echo "Using container engine: ${CONTAINER_CMD}"

# --- Setup Output Directory ---

# Create the 'dist' directory and set maximum permissions (0777) to ensure 
# the container user can write build artifacts back to the host volume.
# NOTE: 0777 is highly permissive; adjust if security is paramount.
mkdir -p "${DIST_DIR}" && chmod 0777 "${DIST_DIR}"
echo "Created writable output directory: ${DIST_DIR}"

# --- Build the Docker Image ---

# Build the image using the detected container engine, tag it, and specify the Dockerfile.
"${CONTAINER_CMD}" build -t "${PYTHON_IMAGE_TAG}" -f "${DOCKERFILE_PATH}" .

# --- Run the Container Interactively ---

# Run the container to drop into an interactive shell for development/testing.
# -ti: Interactive and pseudo-TTY allocation.
# --rm: Remove the container filesystem after the container exits.
# -w /opt/aleph-sdk-python: Set the working directory inside the container.
# -v "$(pwd)/dist": Mount the host's dist directory to the container's output path.
# --entrypoint /bin/bash: Override the default entrypoint to open a shell.
"${CONTAINER_CMD}" run -ti --rm \
  -w /opt/aleph-sdk-python \
  -v "$(pwd)/dist":/opt/aleph-sdk-python/dist \
  --entrypoint /bin/bash \
  "${PYTHON_IMAGE_TAG}"
