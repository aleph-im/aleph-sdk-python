# aleph-sdk-python

Python SDK for the Aleph.im network, a next-generation network for decentralized big-data applications.

Development follows the [Aleph Whitepaper](https://github.com/aleph-im/aleph-whitepaper).

## Documentation

The latest (incomplete) documentation is available at <https://docs.aleph.im/libraries/python-sdk/>.  
For full details, refer to the docstrings in the source code.

## Requirements

### Linux

Some cryptographic functionality uses the secp256k1 curve and requires installing [libsecp256k1](https://github.com/bitcoin-core/secp256k1).

```sh
apt-get install -y python3-pip libsecp256k1-dev
```

Using some chains may also require installing `libgmp3-dev`.

### macOS

This project does not support Python 3.12 on macOS. Please use Python 3.11 instead.

```sh
brew install secp256k1
```

## Installation

Install from [PyPI](https://pypi.org/project/aleph-sdk-python/):

```sh
pip install aleph-sdk-python
```

### Additional dependencies

Some functionality requires extra dependencies. For example:

```sh
pip install 'aleph-sdk-python[solana,dns]'
```

Available extras:

- `solana` — Solana accounts and signatures  
- `cosmos` — Substrate/Cosmos accounts and signatures  
- `nuls2` — NULS2 accounts and signatures  
- `polkadot` — Polkadot accounts and signatures  
- `ledger` — Ledger hardware wallet support (see [Usage with LedgerHQ hardware](#usage-with-ledgerhq-hardware))  
- `mqtt` — MQTT-related functionality (see `examples/mqtt.py`)  
- `docs` — Build the documentation (see [Generating the documentation](#generating-the-documentation-deprecated))  
- `dns` — DNS-related functionality  
- `all` — Installs all extras  

## Installation for development

Set up a virtual environment using [hatch](https://hatch.pypa.io/):

```sh
hatch shell
```

Then install the SDK from source with all extras:

```sh
pip install -e '.[all]'
```

### Running tests & Hatch scripts

Use the Hatch test environment to run tests:

```sh
hatch run testing:run
```

Run `hatch env show` to see all environments and scripts.

### Generating the documentation [DEPRECATED]

The documentation is built with [Sphinx](https://www.sphinx-doc.org/).

Install the SDK with the `docs` extras:

```sh
pip install -e '.[docs]'
```

Then build the docs:

```sh
cd docs
make html
```

## Usage with LedgerHQ hardware

The SDK supports signatures using [app-ethereum](https://github.com/LedgerHQ/app-ethereum), the Ethereum app for Ledger hardware wallets.

Tested on Linux (amd64). Let us know if it works on other operating systems.

Using a Ledger device on Linux requires root access or udev rules. Unlock the device before using the SDK functions.

### Debian / Ubuntu

Install [ledger-wallets-udev](https://packages.debian.org/bookworm/ledger-wallets-udev):

```sh
sudo apt-get install ledger-wallets-udev
```

### NixOS

Configure:

```nix
hardware.ledger.enable = true;
```

### Other Linux systems

See <https://github.com/LedgerHQ/udev-rules>.
