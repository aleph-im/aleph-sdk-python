import os
from pathlib import Path
from shutil import which
from typing import Optional

from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    CONFIG_HOME: Optional[str] = None

    # In case the user does not want to bother with handling private keys himself,
    # do an ugly and insecure write and read from disk to this file.
    PRIVATE_KEY_FILE: Path = Field(
        default=Path("ethereum.key"),
        description="Path to the private key used to sign messages",
    )

    PRIVATE_MNEMONIC_FILE: Path = Field(
        default=Path("substrate.mnemonic"),
        description="Path to the mnemonic used to create Substrate keypairs",
    )

    PRIVATE_KEY_STRING: Optional[str] = None
    API_HOST: str = "https://api2.aleph.im"
    MAX_INLINE_SIZE: int = 50000
    API_UNIX_SOCKET: Optional[str] = None
    REMOTE_CRYPTO_HOST: Optional[str] = None
    REMOTE_CRYPTO_UNIX_SOCKET: Optional[str] = None
    ADDRESS_TO_USE: Optional[str] = None

    DEFAULT_RUNTIME_ID: str = (
        "f873715dc2feec3833074bd4b8745363a0e0093746b987b4c8191268883b2463"  # Debian 12 official runtime
    )
    DEFAULT_VM_MEMORY: int = 256
    DEFAULT_VM_VCPUS: int = 1
    DEFAULT_VM_TIMEOUT: float = 30.0

    CODE_USES_SQUASHFS: bool = which("mksquashfs") is not None  # True if command exists

    # Dns resolver
    DNS_IPFS_DOMAIN = "ipfs.public.aleph.sh"
    DNS_PROGRAM_DOMAIN = "program.public.aleph.sh"
    DNS_INSTANCE_DOMAIN = "instance.public.aleph.sh"
    DNS_STATIC_DOMAIN = "static.public.aleph.sh"
    DNS_RESOLVERS = ["9.9.9.9", "1.1.1.1"]

    class Config:
        env_prefix = "ALEPH_"
        case_sensitive = False
        env_file = ".env"


# Settings singleton
settings = Settings()

if settings.CONFIG_HOME is None:
    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    if xdg_data_home is not None:
        os.environ["ALEPH_CONFIG_HOME"] = str(Path(xdg_data_home, ".aleph-im"))
    else:
        home = os.path.expanduser("~")
        os.environ["ALEPH_CONFIG_HOME"] = str(Path(home, ".aleph-im"))

    settings = Settings()

assert settings.CONFIG_HOME
if str(settings.PRIVATE_KEY_FILE) == "ethereum.key":
    settings.PRIVATE_KEY_FILE = Path(
        settings.CONFIG_HOME, "private-keys", "ethereum.key"
    )

if str(settings.PRIVATE_MNEMONIC_FILE) == "substrate.mnemonic":
    settings.PRIVATE_MNEMONIC_FILE = Path(
        settings.CONFIG_HOME, "private-keys", "substrate.mnemonic"
    )
