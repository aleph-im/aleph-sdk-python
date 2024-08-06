#!/usr/bin/env bash

set -euo pipefail

podman build -t aleph-sdk-ubuntu:24.04 -f tests/ubuntu-24.04.dockerfile .
podman run -ti --rm -v $(pwd):/mnt aleph-sdk-ubuntu:24.04 bash
