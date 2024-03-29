import asyncio

import click
from aleph_message.models import StoreMessage
from aleph_message.status import MessageStatus

from aleph.sdk.chains.common import get_fallback_private_key
from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.client import AuthenticatedAlephHttpClient
from aleph.sdk.conf import settings

DEFAULT_SERVER = "https://api2.aleph.im"


async def print_output_hash(message: StoreMessage, status: MessageStatus):
    print("Successfully created STORE message")
    print(f"File hash ({message.content.item_type}): {message.content.item_hash}")
    print("Sender: ", message.sender)
    print(f"Message hash: {message.item_hash}")
    print(
        f"Explorer URL: https://explorer.aleph.im/address/{message.chain.value}/{message.sender}/message/{message.item_hash}"
    )


async def do_upload(account, engine, channel, filename=None, file_hash=None):
    async with AuthenticatedAlephHttpClient(
        account=account, api_server=settings.API_HOST
    ) as session:
        print(filename, account.get_address())
        if filename:
            try:
                with open(filename, "rb") as f:
                    # Do something with the file
                    content = f.read()
                    if len(content) > 4 * 1024 * 1024 and engine == "STORAGE":
                        print("File too big for native STORAGE engine")
                        return
                    message, status = await session.create_store(
                        file_content=content,
                        channel=channel,
                        storage_engine=engine.lower(),
                    )
            except IOError:
                print("File not accessible")
                raise

        elif file_hash:
            message, status = await session.create_store(
                file_hash=file_hash,
                channel=channel,
                storage_engine=engine.lower(),
            )

        await print_output_hash(message, status)


@click.command()
@click.argument(
    "filename",
)
@click.option(
    "--pkey",
    envvar="PKEY",
    default=None,
    help="Account private key (optional, will default to device.key file)",
)
@click.option(
    "--storage-engine",
    default="IPFS",
    help="Storage engine to use (default: IPFS)",
    type=click.Choice(["STORAGE", "IPFS"], case_sensitive=False),
)
@click.option(
    "--channel",
    envvar="ALEPH_CHANNEL",
    default="TEST",
    help="Channel to write in (default: TEST)",
)
def main(filename, pkey=None, storage_engine="IPFS", channel="TEST"):
    """Uploads or store FILENAME.

    If FILENAME is an IPFS multihash and IPFS is selected as an engine (default), don't try to upload, just pin it to the network.
    Else, uploads the file to the network before pining it.
    """
    if pkey is None:
        pkey = get_fallback_private_key()

    account = ETHAccount(private_key=pkey)

    upload_filename = None
    upload_hash = None

    if (
        46 <= len(filename) <= 48
        and filename.startswith("Q")
        and storage_engine == "IPFS"
    ):
        upload_hash = filename
    else:
        upload_filename = filename

    asyncio.run(
        do_upload(
            account,
            storage_engine,
            channel,
            filename=upload_filename,
            file_hash=upload_hash,
        )
    )


if __name__ == "__main__":
    main()
