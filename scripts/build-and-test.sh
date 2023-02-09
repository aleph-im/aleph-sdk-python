#!/bin/sh

set -euf

# Use Podman if installed, else use Docker
if hash podman 2> /dev/null
then
  DOCKER_COMMAND=podman
else
  DOCKER_COMMAND=docker
fi

$DOCKER_COMMAND build -t aleph-sdk-python -f docker/Dockerfile .
$DOCKER_COMMAND run -ti --rm --entrypoint /opt/venv/bin/pytest aleph-sdk-python /opt/aleph-sdk-python/ "$@"
$DOCKER_COMMAND run -ti --rm --entrypoint /opt/venv/bin/mypy aleph-sdk-python /opt/aleph-sdk-python/src/ --ignore-missing-imports
