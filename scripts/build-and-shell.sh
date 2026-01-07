#!/bin/sh
"""
@fileoverview Shell script to build and launch a disposable, interactive container 
for the aleph-sdk-python development environment, prioritizing Podman over Docker.
"""

# Enable strict mode: exit on errors (-e), exit on unbound variables (-u), 
# and disable pathname expansion (-f).
set -euf

# --- 1. DETECT CONTAINER ENGINE ---

# Check for Podman first, if found, use it. Otherwise, default to Docker.
DOCKER_COMMAND=""
if command -v podman > /dev/null 2>&1
then
  DOCKER_COMMAND=podman
elif command -v docker > /dev/null 2>&1
then
  DOCKER_COMMAND=docker
else
  # CRITICAL: Exit if neither Podman nor Docker is available.
  echo "Error: Neither 'podman' nor 'docker' command was found." >&2
  exit 1
fi

echo "Using container engine: ${DOCKER_COMMAND}"

# --- 2. BUILD THE IMAGE ---

IMAGE_NAME="aleph-sdk-python"
DOCKERFILE_PATH="docker/python-3.9.dockerfile"

echo "Building image ${IMAGE_NAME} using ${DOCKERFILE_PATH}..."
# Build the image using the detected command. The '.' means the context is the current directory.
${DOCKER_COMMAND} build -t ${IMAGE_NAME} -f ${DOCKERFILE_PATH} .

# --- 3. RUN INTERACTIVE CONTAINER ---

# Launch the container with:
# -t (Allocate a pseudo-terminal) and -i (Keep STDIN open) for interactivity.
# --rm (Automatically remove the container when it exits).
# --entrypoint /bin/bash (Override the default entrypoint to drop into a shell).
# -v "$(pwd)":/opt/aleph-sdk-python (Mount the current project directory into the container).
echo "Launching interactive shell in the container..."
${DOCKER_COMMAND} run \
  -ti \
  --rm \
  --entrypoint /bin/bash \
  -v "$(pwd)":/opt/${IMAGE_NAME} \
  ${IMAGE_NAME}
