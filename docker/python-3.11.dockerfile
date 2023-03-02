FROM python:3.11-bullseye
MAINTAINER The aleph.im project

RUN apt-get update && apt-get -y upgrade && apt-get install -y \
     libsecp256k1-dev \
     && rm -rf /var/lib/apt/lists/*

RUN useradd -s /bin/bash --create-home user
RUN mkdir /opt/venv
RUN mkdir /opt/aleph-sdk-python/
RUN chown user:user /opt/venv
RUN chown user:user /opt/aleph-sdk-python

USER user
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --upgrade pip wheel twine

# Preinstall dependencies for faster steps
RUN pip install --upgrade secp256k1 coincurve aiohttp eciespy python-magic typer
RUN pip install --upgrade 'aleph-message~=0.3.1' pynacl base58
RUN pip install --upgrade pytest pytest-cov pytest-asyncio mypy types-setuptools pytest-asyncio fastapi httpx requests

WORKDIR /opt/aleph-sdk-python/
COPY . .
USER root
RUN chown -R user:user /opt/aleph-sdk-python

RUN git config --global --add safe.directory /opt/aleph-sdk-python
RUN pip install -e .[testing,ethereum,solana,tezos]

RUN mkdir /data
RUN chown user:user /data
ENV ALEPH_PRIVATE_KEY_FILE=/data/secret.key

WORKDIR /home/user
USER user
