from pathlib import Path
from typing import Optional

import typer
from aleph_message.models import MessageType

from aleph_client import UserSession
from aleph_client.account import _load_account
from aleph_client.commands import help_strings
from aleph_client.commands.message import forget_messages
from aleph_client.commands.utils import setup_logging
from aleph_client.conf import settings
from aleph_client.types import AccountFromPrivateKey

app = typer.Typer()


@app.command()
def forget(
    key: str = typer.Argument(..., help="Aggregate item hash to be removed."),
    reason: Optional[str] = typer.Option(
        None, help="A description of why the messages are being forgotten"
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
    """Forget all the messages composing an aggregate."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    with UserSession(api_server=settings.API_HOST) as session:
        message_response = session.get_messages(
            addresses=[account.get_address()],
            message_type=MessageType.aggregate.value,
            content_keys=[key],
        )
    hash_list = [message["item_hash"] for message in message_response.messages]
    forget_messages(account, hash_list, reason, channel)
