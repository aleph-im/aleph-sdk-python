import asyncio
import os
from typing import Optional, Tuple, Any

import click
from aleph_message.models import StoreMessage
from aleph_message.status import MessageStatus
from aleph_message.exceptions import InvalidMessage

from aleph.sdk.chains.common import get_fallback_private_key
from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.client import AuthenticatedAlephHttpClient
from aleph.sdk.conf import settings

# Max file size for the Aleph native STORAGE engine (currently 4 MiB)
MAX_STORAGE_SIZE_BYTES = 4 * 1024 * 1024 

async def print_output_hash(message: StoreMessage, status: MessageStatus) -> None:
    """Prints the successful output details of the uploaded/pinned file."""
    print("Successfully created STORE message")
    print(f"File hash ({message.content.item_type}): {message.content.item_hash}")
    print("Sender: ", message.sender)
    print(f"Message hash: {message.item_hash}")
    print(
        f"Explorer URL: https://explorer.aleph.im/address/{message.chain.value}/{message.sender}/message/{message.item_hash}"
    )


def is_ipfs_multihash(filename: str) -> bool:
    """Checks if the filename string looks like a standard IPFS multihash (Q...)."""
    # Standard V0 IPFS hash is 46 chars long and starts with 'Qm' (not just 'Q').
    # The original code used 46 <= len(filename) <= 48 and starts with 'Q',
    # we maintain compatibility with the broader check for robustness.
    return 46 <= len(filename) <= 48 and filename.startswith("Q")


async def do_upload(
    account: ETHAccount, 
    engine: str, 
    channel: str, 
    filename: Optional[str] = None, 
    file_hash: Optional[str] = None
) -> None:
    """Handles file content upload or hash pinning using the authenticated Aleph client."""
    
    # Use settings.API_HOST for API server URL consistency, as defined in Aleph SDK.
    async with AuthenticatedAlephHttpClient(
        account=account, api_server=settings.API_HOST
    ) as session:
        print(f"Attempting upload for file: {filename} from sender: {account.get_address()}")

        if filename:
            try:
                # Synchronous file reading is acceptable here as it happens before the async network call,
                # but for very large files, this would ideally be in a thread pool (using asyncio.to_thread).
                with open(filename, "rb") as f:
                    content = f.read()
                
                # Check for file size constraint based on the storage engine
                if len(content) > MAX_STORAGE_SIZE_BYTES and engine.upper() == "STORAGE":
                    print(f"File size ({len(content) / 1024 / 1024:.2f} MiB) exceeds the native STORAGE engine limit of 4 MiB.")
                    return
                
                # Create a store message by uploading the file content
                message, status = await session.create_store(
                    file_content=content,
                    channel=channel,
                    storage_engine=engine.lower(),
                )
            except FileNotFoundError:
                print(f"Error: File '{filename}' not found.")
                # Re-raise the exception to be handled by the click framework if necessary
                raise click.FileError(filename=filename, hint="File not accessible or does not exist.")
            except InvalidMessage as e:
                print(f"Error creating store message: {e}")
                return
            
        elif file_hash:
            # Create a store message by pinning an existing file hash
            message, status = await session.create_store(
                file_hash=file_hash,
                channel=channel,
                storage_engine=engine.lower(),
            )
        
        else:
            print("Error: Must provide either a filename or a file hash for processing.")
            return

        await print_output_hash(message, status)


@click.command(help="Uploads or stores a FILENAME/IPFS hash to the aleph.im network.")
@click.argument(
    "filename",
)
@click.option(
    "--pkey",
    envvar="PKEY",
    default=None,
    help="Account private key (optional, defaults to device.key file).",
)
@click.option(
    "--storage-engine",
    default="IPFS",
    help="Storage engine to use (default: IPFS).",
    type=click.Choice(["STORAGE", "IPFS"], case_sensitive=False),
)
@click.option(
    "--channel",
    envvar="ALEPH_CHANNEL",
    default="TEST",
    help="Channel to write the message in (default: TEST).",
)
def main(filename: str, pkey: Optional[str], storage_engine: str, channel: str):
    """
    Determines whether to upload a local file or pin an existing IPFS hash, 
    and initiates the transaction on the Aleph.im network.
    """
    
    # 1. Private Key / Account Handling
    if pkey is None:
        try:
            pkey = get_fallback_private_key()
        except FileNotFoundError:
             raise click.ClickException("Private key not found. Set PKEY environment variable, use --pkey, or ensure device.key exists.")

    account = ETHAccount(private_key=pkey)

    # 2. Determine if input is a local file or an IPFS hash to be pinned
    upload_filename: Optional[str] = None
    upload_hash: Optional[str] = None

    if is_ipfs_multihash(filename) and storage_engine.upper() == "IPFS":
        # Pinning an existing IPFS hash
        upload_hash = filename
        print(f"Detected IPFS hash, pinning hash: {upload_hash}")
    else:
        # Uploading a local file
        upload_filename = filename
        print(f"Uploading file content: {upload_filename} (Engine: {storage_engine})")


    # 3. Run the asynchronous upload logic
    try:
        asyncio.run(
            do_upload(
                account,
                storage_engine,
                channel,
                filename=upload_filename,
                file_hash=upload_hash,
            )
        )
    except click.ClickException as e:
        # Re-raise explicit Click exceptions for clean CLI output
        raise e
    except Exception as e:
        # Catch other unexpected errors during the async execution
        raise click.ClickException(f"An unexpected error occurred during execution: {e}")


if __name__ == "__main__":
    main()
