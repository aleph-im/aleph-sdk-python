import json
import os.path
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Dict, List

import typer
from aleph_message.models import AlephMessage

from aleph_client import AuthenticatedUserSession, UserSession
from aleph_client.account import _load_account
from aleph_client.commands import help_strings
from aleph_client.commands.utils import (
    setup_logging,
    input_multiline,
)
from aleph_client.conf import settings
from aleph_client.types import AccountFromPrivateKey, StorageEnum

app = typer.Typer()


@app.command()
def post(
    path: Optional[Path] = typer.Option(
        None,
        help="Path to the content you want to post. If omitted, you can input your content directly",
    ),
    type: str = typer.Option("test", help="Text representing the message object type"),
    ref: Optional[str] = typer.Option(None, help=help_strings.REF),
    channel: str = typer.Option(settings.DEFAULT_CHANNEL, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(
        settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    debug: bool = False,
):
    """Post a message on Aleph.im."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)
    content: Dict

    if path:
        if not path.is_file():
            typer.echo(f"Error: File not found: '{path}'")
            raise typer.Exit(code=1)

        file_size = os.path.getsize(path)
        storage_engine = (
            StorageEnum.ipfs if file_size > 4 * 1024 * 1024 else StorageEnum.storage
        )

        with open(path, "r") as fd:
            content = json.load(fd)

    else:
        content_raw = input_multiline()
        storage_engine = (
            StorageEnum.ipfs
            if len(content_raw) > 4 * 1024 * 1024
            else StorageEnum.storage
        )
        try:
            content = json.loads(content_raw)
        except json.decoder.JSONDecodeError:
            typer.echo("Not valid JSON")
            raise typer.Exit(code=2)

    with AuthenticatedUserSession(
        account=account, api_server=settings.API_HOST
    ) as session:
        message, status = session.create_post(
            post_content=content,
            post_type=type,
            ref=ref,
            channel=channel,
            inline=True,
            storage_engine=storage_engine,
        )
    typer.echo(message.json(indent=4))


@app.command()
def amend(
    hash: str = typer.Argument(..., help="Hash reference of the message to amend"),
    private_key: Optional[str] = typer.Option(
        settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    debug: bool = False,
):
    """Amend an existing Aleph message."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)
    with AuthenticatedUserSession(
        account=account, api_server=settings.API_HOST
    ) as session:
        existing_message: AlephMessage = session.get_message(item_hash=hash)

        editor: str = os.getenv("EDITOR", default="nano")
        with tempfile.NamedTemporaryFile(suffix="json") as fd:
            # Fill in message template
            fd.write(existing_message.content.json(indent=4).encode())
            fd.seek(0)

            # Launch editor
            subprocess.run([editor, fd.name], check=True)

            # Read new message
            fd.seek(0)
            new_content_json = fd.read()

        content_type = type(existing_message).__annotations__["content"]
        new_content_dict = json.loads(new_content_json)
        new_content = content_type(**new_content_dict)
        new_content.ref = existing_message.item_hash
        typer.echo(new_content)
        message, _status = session.submit(
            content=new_content.dict(),
            message_type=existing_message.type,
            channel=existing_message.channel,
        )
        typer.echo(f"{message.json(indent=4)}")


def forget_messages(
    account: AccountFromPrivateKey,
    hashes: List[str],
    reason: Optional[str],
    channel: str,
):
    with AuthenticatedUserSession(
        account=account, api_server=settings.API_HOST
    ) as session:
        message, status = session.forget(
            hashes=hashes,
            reason=reason,
            channel=channel,
        )
    typer.echo(f"{message.json(indent=4)}")


@app.command()
def forget(
    hashes: str = typer.Argument(
        ..., help="Comma separated list of hash references of messages to forget"
    ),
    reason: Optional[str] = typer.Option(
        None, help="A description of why the messages are being forgotten."
    ),
    channel: str = typer.Option(settings.DEFAULT_CHANNEL, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(
        settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    debug: bool = False,
):
    """Forget an existing Aleph message."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    hash_list: List[str] = hashes.split(",")
    forget_messages(account, hash_list, reason, channel)


@app.command()
def watch(
    ref: str = typer.Argument(..., help="Hash reference of the message to watch"),
    indent: Optional[int] = typer.Option(None, help="Number of indents to use"),
    debug: bool = False,
):
    """Watch a hash for amends and print amend hashes"""

    setup_logging(debug)

    with UserSession(api_server=settings.API_HOST) as session:
        original: AlephMessage = session.get_message(item_hash=ref)

        for message in session.watch_messages(
            refs=[ref], addresses=[original.content.address]
        ):
            typer.echo(f"{message.json(indent=indent)}")
