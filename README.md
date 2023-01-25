
# aleph-sdk-python
Python SDK for the Aleph.im network, next generation network of decentralized big data applications.

Development follows the [Aleph Whitepaper](https://github.com/aleph-im/aleph-whitepaper).

## Documentation
Documentation (albeit still vastly incomplete as it is a work in progress) can be found at [http://aleph-sdk-python.readthedocs.io/](http://aleph-sdk-python.readthedocs.io/) or built from this repo with:

```shell
$ python setup.py docs
```

## Requirements
### Linux 
Some cryptographic functionalities use curve secp256k1 and require installing [libsecp256k1](https://github.com/bitcoin-core/secp256k1).

```shell
$ apt-get install -y python3-pip libsecp256k1-dev
```
Using some chains may also require installing `libgmp3-dev`.

### macOs 
```shell
$ brew tap cuber/homebrew-libsecp256k1
$ brew install libsecp256k1
```

## Installation
Using pip and [PyPI](https://pypi.org/project/aleph-sdk-python/):

```shell
$ pip install aleph-sdk-python[ethereum,solana,tezos]
```

## Installation for development
To install from source and still be able to modify the source code:

```shell
$ pip install -e .[testing]
```
or 
```shell
$ python setup.py develop
```
