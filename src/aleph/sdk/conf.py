import json
import logging
import os
from pathlib import Path
from shutil import which
from typing import Dict, Optional, Union

from aleph_message.models import Chain
from aleph_message.models.execution.environment import HypervisorType
from pydantic import BaseModel, BaseSettings, Field

from aleph.sdk.types import ChainInfo

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    CONFIG_HOME: Optional[str] = None

    CONFIG_FILE: Path = Field(
        default=Path("config.json"),
        description="Path to the JSON file containing chain account configurations",
    )

    # In case the user does not want to bother with handling private keys himself,
    # do an ugly and insecure write and read from disk to this file.
    PRIVATE_KEY_FILE: Path = Field(
        default=Path("ethereum.key"),
        description="Path to the private key used to sign messages and transactions",
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
    HTTP_REQUEST_TIMEOUT = 15.0

    DEFAULT_CHANNEL: str = "ALEPH-CLOUDSOLUTIONS"
    DEFAULT_RUNTIME_ID: str = (
        "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696"
    )
    DEBIAN_11_ROOTFS_ID: str = (
        "887957042bb0e360da3485ed33175882ce72a70d79f1ba599400ff4802b7cee7"
    )
    DEBIAN_12_ROOTFS_ID: str = (
        "6e30de68c6cedfa6b45240c2b51e52495ac6fb1bd4b36457b3d5ca307594d595"
    )
    UBUNTU_22_ROOTFS_ID: str = (
        "77fef271aa6ff9825efa3186ca2e715d19e7108279b817201c69c34cedc74c27"
    )
    DEBIAN_11_QEMU_ROOTFS_ID: str = (
        "f7e68c568906b4ebcd3cd3c4bfdff96c489cd2a9ef73ba2d7503f244dfd578de"
    )
    DEBIAN_12_QEMU_ROOTFS_ID: str = (
        "b6ff5c3a8205d1ca4c7c3369300eeafff498b558f71b851aa2114afd0a532717"
    )
    UBUNTU_22_QEMU_ROOTFS_ID: str = (
        "4a0f62da42f4478544616519e6f5d58adb1096e069b392b151d47c3609492d0c"
    )

    DEFAULT_CONFIDENTIAL_FIRMWARE: str = (
        "ba5bb13f3abca960b101a759be162b229e2b7e93ecad9d1307e54de887f177ff"
    )
    DEFAULT_CONFIDENTIAL_FIRMWARE_HASH: str = (
        "89b76b0e64fe9015084fbffdf8ac98185bafc688bfe7a0b398585c392d03c7ee"
    )

    DEFAULT_ROOTFS_SIZE: int = 20_480
    DEFAULT_INSTANCE_MEMORY: int = 2_048
    DEFAULT_HYPERVISOR: HypervisorType = HypervisorType.qemu

    DEFAULT_VM_MEMORY: int = 256
    DEFAULT_VM_VCPUS: int = 1
    DEFAULT_VM_TIMEOUT: float = 30.0

    CODE_USES_SQUASHFS: bool = which("mksquashfs") is not None  # True if command exists

    VM_URL_PATH = "https://aleph.sh/vm/{hash}"
    VM_URL_HOST = "https://{hash_base32}.aleph.sh"

    # Web3Provider settings
    TOKEN_DECIMALS = 18
    TX_TIMEOUT = 60 * 3
    CHAINS: Dict[Union[Chain, str], ChainInfo] = {
        # TESTNETS
        "SEPOLIA": ChainInfo(
            chain_id=11155111,
            rpc="https://eth-sepolia.public.blastapi.io",
            token="0xc4bf5cbdabe595361438f8c6a187bdc330539c60",
            super_token="0x22064a21fee226d8ffb8818e7627d5ff6d0fc33a",
            active=False,
        ),
        # MAINNETS
        Chain.ARBITRUM: ChainInfo(
            chain_id=42161,
            rpc="https://arbitrum-one.publicnode.com",
        ),
        Chain.AVAX: ChainInfo(
            chain_id=43114,
            rpc="https://api.avax.network/ext/bc/C/rpc",
            token="0xc0Fbc4967259786C743361a5885ef49380473dCF",
            super_token="0xc0Fbc4967259786C743361a5885ef49380473dCF",
        ),
        Chain.BASE: ChainInfo(
            chain_id=8453,
            rpc="https://base-mainnet.public.blastapi.io",
            token="0xc0Fbc4967259786C743361a5885ef49380473dCF",
            super_token="0xc0Fbc4967259786C743361a5885ef49380473dCF",
        ),
        Chain.BLAST: ChainInfo(
            chain_id=81457,
            rpc="https://blastl2-mainnet.public.blastapi.io",
        ),
        Chain.BOB: ChainInfo(
            chain_id=60808,
            rpc="https://bob-mainnet.public.blastapi.io",
        ),
        Chain.BSC: ChainInfo(
            chain_id=56,
            rpc="https://binance.llamarpc.com",
            token="0x82D2f8E02Afb160Dd5A480a617692e62de9038C4",
            active=False,
        ),
        Chain.CYBER: ChainInfo(
            chain_id=7560,
            rpc="https://rpc.cyber.co",
        ),
        Chain.ETH: ChainInfo(
            chain_id=1,
            rpc="https://eth-mainnet.public.blastapi.io",
            token="0x27702a26126e0B3702af63Ee09aC4d1A084EF628",
        ),
        Chain.FRAXTAL: ChainInfo(
            chain_id=252,
            rpc="https://rpc.frax.com",
        ),
        Chain.LINEA: ChainInfo(
            chain_id=59144,
            rpc="https://linea-rpc.publicnode.com",
        ),
        Chain.LISK: ChainInfo(
            chain_id=1135,
            rpc="https://rpc.api.lisk.com",
        ),
        Chain.METIS: ChainInfo(
            chain_id=1088,
            rpc="https://metis.drpc.org",
        ),
        Chain.MODE: ChainInfo(
            chain_id=34443,
            rpc="https://mode.drpc.org",
        ),
        Chain.OPTIMISM: ChainInfo(
            chain_id=10,
            rpc="https://optimism-rpc.publicnode.com",
        ),
        Chain.POL: ChainInfo(
            chain_id=137,
            rpc="https://polygon.gateway.tenderly.co",
        ),
        Chain.WORLDCHAIN: ChainInfo(
            chain_id=480,
            rpc="https://worldchain-mainnet.gateway.tenderly.co",
        ),
        Chain.ZORA: ChainInfo(
            chain_id=7777777,
            rpc="https://rpc.zora.energy/",
        ),
    }
    # Add all placeholders to allow easy dynamic setup of CHAINS
    CHAINS_SEPOLIA_ACTIVE: Optional[bool] = None
    CHAINS_ETH_ACTIVE: Optional[bool] = None
    CHAINS_AVAX_ACTIVE: Optional[bool] = None
    CHAINS_BASE_ACTIVE: Optional[bool] = None
    CHAINS_BSC_ACTIVE: Optional[bool] = None
    CHAINS_ARBITRUM_ACTIVE: Optional[bool] = None
    CHAINS_BLAST_ACTIVE: Optional[bool] = None
    CHAINS_BOB_ACTIVE: Optional[bool] = None
    CHAINS_CYBER_ACTIVE: Optional[bool] = None
    CHAINS_FRAXTAL_ACTIVE: Optional[bool] = None
    CHAINS_LINEA_ACTIVE: Optional[bool] = None
    CHAINS_LISK_ACTIVE: Optional[bool] = None
    CHAINS_METIS_ACTIVE: Optional[bool] = None
    CHAINS_MODE_ACTIVE: Optional[bool] = None
    CHAINS_OPTIMISM_ACTIVE: Optional[bool] = None
    CHAINS_POL_ACTIVE: Optional[bool] = None
    CHAINS_WORLDCHAIN_ACTIVE: Optional[bool] = None
    CHAINS_ZORA_ACTIVE: Optional[bool] = None

    CHAINS_SEPOLIA_RPC: Optional[str] = None
    CHAINS_ETH_RPC: Optional[str] = None
    CHAINS_AVAX_RPC: Optional[str] = None
    CHAINS_BASE_RPC: Optional[str] = None
    CHAINS_BSC_RPC: Optional[str] = None
    CHAINS_ARBITRUM_RPC: Optional[str] = None
    CHAINS_BLAST_RPC: Optional[str] = None
    CHAINS_BOB_RPC: Optional[str] = None
    CHAINS_CYBER_RPC: Optional[str] = None
    CHAINS_FRAXTAL_RPC: Optional[str] = None
    CHAINS_LINEA_RPC: Optional[str] = None
    CHAINS_LISK_RPC: Optional[str] = None
    CHAINS_METIS_RPC: Optional[str] = None
    CHAINS_MODE_RPC: Optional[str] = None
    CHAINS_OPTIMISM_RPC: Optional[str] = None
    CHAINS_POL_RPC: Optional[str] = None
    CHAINS_WORLDCHAIN_RPC: Optional[str] = None
    CHAINS_ZORA_RPC: Optional[str] = None

    DEFAULT_CHAIN: Chain = Chain.ETH

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


class MainConfiguration(BaseModel):
    """
    Intern Chain Management with Account.
    """

    path: Path
    chain: Chain

    class Config:
        use_enum_values = True


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
if str(settings.CONFIG_FILE) == "config.json":
    settings.CONFIG_FILE = Path(settings.CONFIG_HOME, "config.json")
    # If Config file exist and well filled we update the PRIVATE_KEY_FILE default
    if settings.CONFIG_FILE.exists():
        try:
            with open(settings.CONFIG_FILE, "r", encoding="utf-8") as f:
                config_data = json.load(f)

            if "path" in config_data:
                settings.PRIVATE_KEY_FILE = Path(config_data["path"])
        except json.JSONDecodeError:
            pass


# Update CHAINS settings and remove placeholders
CHAINS_ENV = [(key[7:], value) for key, value in settings if key.startswith("CHAINS_")]
for fields, value in CHAINS_ENV:
    if value:
        chain, field = fields.split("_", 1)
        chain = chain if chain not in Chain.__members__ else Chain[chain]
        field = field.lower()
        settings.CHAINS[chain].__dict__[field] = value
    settings.__delattr__(f"CHAINS_{fields}")


def save_main_configuration(file_path: Path, data: MainConfiguration):
    """
    Synchronously save a single ChainAccount object as JSON to a file.
    """
    with file_path.open("w") as file:
        data_serializable = data.dict()
        data_serializable["path"] = str(data_serializable["path"])
        json.dump(data_serializable, file, indent=4)


def load_main_configuration(file_path: Path) -> Optional[MainConfiguration]:
    """
    Synchronously load the private key and chain type from a file.
    If the file does not exist or is empty, return None.
    """
    if not file_path.exists() or file_path.stat().st_size == 0:
        logger.debug(f"File {file_path} does not exist or is empty. Returning None.")
        return None

    try:
        with file_path.open("rb") as file:
            content = file.read()
            data = json.loads(content.decode("utf-8"))
            return MainConfiguration(**data)
    except UnicodeDecodeError as e:
        logger.error(f"Unable to decode {file_path} as UTF-8: {e}")
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON format in {file_path}.")

    return None
