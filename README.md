
# aleph-sdk-python
Python SDK for the Aleph.im network, next generation network of decentralized big data applications.

Development follows the [Aleph Whitepaper](https://github.com/aleph-im/aleph-whitepaper).

## Documentation
The latest documentation, albeit incomplete, is available at [https://docs.aleph.im/libraries/python-sdk/](https://docs.aleph.im/libraries/python-sdk/).

For the full documentation, please refer to the docstrings in the source code.

## Requirements
### Linux 
Some cryptographic functionalities use curve secp256k1 and require installing [libsecp256k1](https://github.com/bitcoin-core/secp256k1).

```shell
$ apt-get install -y python3-pip libsecp256k1-dev
```
Using some chains may also require installing `libgmp3-dev`.

### macOs
This project does not support Python 3.12 on macOS. Please use Python 3.11 instead.
```shell
$ brew tap cuber/homebrew-libsecp256k1
$ brew install libsecp256k1
```

## Installation
Using pip and [PyPI](https://pypi.org/project/aleph-sdk-python/):

```shell
$ pip install aleph-sdk-python
```

### Additional dependencies
Some functionalities require additional dependencies. They can be installed like this:

```shell
$ pip install aleph-sdk-python[ethereum, dns]
```

The following extra dependencies are available:
- `ethereum` for Ethereum and Ethereum-compatible chains
- `solana` for Solana accounts and signatures
- `cosmos` for Substrate/Cosmos accounts and signatures
- `nuls2` for NULS2 accounts and signatures
- `polkadot` for Polkadot accounts and signatures
- `ledger` for Ledger hardware wallet support, see [Usage with LedgerHQ hardware](#usage-with-ledgerhq-hardware)
- `mqtt` for MQTT-related functionalities, see [examples/mqtt.py](examples/mqtt.py)
- `docs` for building the documentation, see [Documentation](#documentation)
- `dns` for DNS-related functionalities
- `all` installs all extra dependencies


## Installation for development
Setup a virtual environment using [hatch](https://hatch.pypa.io/):
```shell
$ hatch shell
```

Then install the SDK from source with all extra dependencies:

```shell
$ pip install -e .[all]
```

### Running tests & Hatch scripts
You can use the test env defined for hatch to run the tests:

```shell
$ hatch run test:run
```

See `hatch env show` for more information about all the environments and their scripts.

### Generating the documentation [DEPRECATED]
The documentation is built using [Sphinx](https://www.sphinx-doc.org/).

To build the documentation, install the SDK with the `docs` extra dependencies:

```shell
$ pip install -e .[docs]
```

Then build the documentation:

```shell
$ cd docs
$ make html
```

## Usage with LedgerHQ hardware

The SDK supports signatures using [app-ethereum](https://github.com/LedgerHQ/app-ethereum),
the Ethereum app for the Ledger hardware wallets.

This has been tested successfully on Linux (amd64).
Let us know if it works for you on other operating systems.

Using a Ledger device on Linux requires root access or the setup of udev rules.

Unlocking the device is required before using the relevant SDK functions.

### Debian / Ubuntu

Install [ledger-wallets-udev](https://packages.debian.org/bookworm/ledger-wallets-udev).

`sudo apt-get install ledger-wallets-udev`

### On NixOS

Configure `hardware.ledger.enable = true`.

### Other Linux systems

See https://github.com/LedgerHQ/udev-rules


