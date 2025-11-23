#!/bin/sh

# Exit immediately if a command exits with a non-zero status (-e).
# Treat unset variables as an error (-u).
# Enable the use of "glob" characters in pathnames, but only if they match (-f).
set -euf

# --- Configuration ---
IMAGE_NAME="aleph-sdk-python"
DOCKERFILE_PATH="docker/python-3.9.dockerfile"
CONTAINER_MOUNT_PATH="/opt/${IMAGE_NAME}"

# --- Determine Container Runtime (Podman vs. Docker) ---

# Use 'command -v' for a more portable and reliable check for the container runtime.
if command -v podman > /dev/null 2>&1; then
    DOCKER_COMMAND=podman
    echo "INFO: Using Podman as the container runtime."
elif command -v docker > /dev/null 2>&1; then
    DOCKER_COMMAND=docker
    echo "INFO: Using Docker as the container runtime."
else
    echo "ERROR: Neither 'podman' nor 'docker' commands were found." >&2
    exit 1
fi

# --- Build the Docker Image ---

# Build the image using the determined command and specified Dockerfile path.
# -t: Tags the image with the defined name.
echo "INFO: Building image ${IMAGE_NAME} using ${DOCKERFILE_PATH}..."
$DOCKER_COMMAND build -t "${IMAGE_NAME}" -f "${DOCKERFILE_PATH}" .

# --- Run the Interactive Development Container ---

# Run the container for interactive development.
# -ti: Allocates a pseudo-TTY and keeps STDIN open (interactive).
# --rm: Automatically remove the container when it exits.
# --entrypoint /bin/bash: Overrides the default entrypoint to provide a shell prompt.
# -v: Mounts the current working directory ($PWD) into the container for source access.
echo "INFO: Running interactive container. Source code mounted at ${CONTAINER_MOUNT_PATH}."
$DOCKER_COMMAND run \
    -ti \
    --rm \
    --entrypoint /bin/bash \
    -v "$(pwd)":"${CONTAINER_MOUNT_PATH}" \
    "${IMAGE_NAME}"
