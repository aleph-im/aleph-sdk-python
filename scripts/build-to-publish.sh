#!/bin/sh

# Exit immediately if a command exits with a non-zero status (-e),
# treat unset variables as an error (-u), and disable filename expansion (-f).
set -euf

# --- 1. Detect Container Runtime ---
# Use 'command -v' for POSIX-compliant existence check.
if command -v podman > /dev/null; then
  DOCKER_COMMAND=podman
elif command -v docker > /dev/null; then
  DOCKER_COMMAND=docker
else
  echo "Error: Neither Podman nor Docker is installed or available in PATH." >&2
  exit 1
fi

echo "Using container runtime: ${DOCKER_COMMAND}"

# --- 2. Setup Host Directory ---
# Create the distribution directory. Default permissions (usually 0755) are used, 
# which is safer than 0777. Permissions issues should ideally be resolved 
# by user management within the Dockerfile.
mkdir -p ./dist

# --- 3. Build Image ---
IMAGE_NAME="aleph-sdk-python"
DOCKERFILE_PATH="docker/python-3.9.dockerfile"

echo "Building image ${IMAGE_NAME}..."
${DOCKER_COMMAND} build -t ${IMAGE_NAME} -f ${DOCKERFILE_PATH} .

# --- 4. Run Container for Interactive Development/Debugging ---
# Runs the container interactively, mounts the 'dist' volume, and drops the user 
# into a Bash shell for subsequent build/test commands.
echo "Starting container and dropping into /bin/bash..."
${DOCKER_COMMAND} run -ti --rm \
  --name aleph-sdk-dev \
  -w /opt/aleph-sdk-python \
  -v "$(pwd)/dist":/opt/aleph-sdk-python/dist \
  --entrypoint /bin/bash \
  ${IMAGE_NAME}
