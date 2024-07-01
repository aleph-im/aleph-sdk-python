FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    libsecp256k1-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create a working virtual environment \
RUN python3 -m venv /opt/venv
RUN /opt/venv/bin/python -m pip install --upgrade pip hatch

WORKDIR /mnt
VOLUME /mnt

# Make it easy to run the tests with the upper arrow
RUN echo "/opt/venv/bin/hatch run testing:test" >> /root/.bash_history
