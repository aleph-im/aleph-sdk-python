#!/usr/bin/env bash

set -euo pipefail

# Allow overriding with env DOCKER_COMMAND, else prefer podman if available, fallback to docker
DOCKER_COMMAND=${DOCKER_COMMAND:-}
if [ -z "$DOCKER_COMMAND" ]; then
  if command -v podman >/dev/null 2>&1; then
    DOCKER_COMMAND=podman
  else
    DOCKER_COMMAND=docker
  fi
fi

mkdir -p ./dist
chmod 0755 ./dist

# Build image (use --pull for freshest base)
$DOCKER_COMMAND build --pull -t aleph-sdk-python -f docker/python-3.9.dockerfile .

# Run container interactively; map dist and run as current user to avoid root-owned files
USER_UID=$(id -u)
USER_GID=$(id -g)

$DOCKER_COMMAND run -ti --rm \
  -w /opt/aleph-sdk-python \
  -v "$(pwd)/dist":/opt/aleph-sdk-python/dist \
  -u "${USER_UID}:${USER_GID}" \
  --entrypoint /bin/bash \
  aleph-sdk-python