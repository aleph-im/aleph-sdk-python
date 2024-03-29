import base64
import binascii
import socket
from dataclasses import dataclass
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    Mapping,
    MutableMapping,
    Optional,
)

AsgiApplication = Callable


@dataclass
class EventHandler:
    filters: List[Dict]
    handler: Callable

    def matches(self, scope: Mapping[str, Any]) -> bool:
        for filter in self.filters:
            # if [filter matches scope]: TODO
            if True:
                return True
        return False


class AlephApp:
    """ASGI compatible wrapper for apps running inside aleph.im Virtual Machines.
    The wrapper adds support to register functions to react to non-HTTP events.
    """

    http_app: Optional[AsgiApplication] = None
    event_handlers: List[EventHandler]

    def __init__(self, http_app: Optional[AsgiApplication] = None):
        self.http_app = http_app
        self.event_handlers = []

    def event(self, filters: List[Dict]):
        """Use this decorator to register event calls.

        ```python
            @app.event(filters=[...])
            def on_event(event):
                ...
        ```
        """

        def inner(func: Callable):
            # Register the event handler
            event_handler = EventHandler(filters=filters, handler=func)
            self.event_handlers.append(event_handler)
            return func

        return inner

    async def __call__(
        self,
        scope: MutableMapping[str, Any],
        receive: Optional[Callable[[], Awaitable[Any]]] = None,
        send: Optional[Callable[[Dict[Any, Any]], Awaitable[Any]]] = None,
    ):
        if scope["type"] in ("http", "websocket", "lifespan"):
            if self.http_app:
                await self.http_app(scope=scope, receive=receive, send=send)
            else:
                raise ValueError("No HTTP app registered")
        elif scope["type"] == "aleph.message":
            for event_handler in self.event_handlers:
                if event_handler.matches(scope):
                    # event_handler.handler(scope=scope, receive=receive, send=send)
                    async def send_handler_result():
                        result = await event_handler.handler(event=scope)
                        if send:
                            await send(result)
                        else:
                            raise ValueError("No send method specified")

                    return send_handler_result()
        else:
            raise ValueError(f"Unknown scope type '{scope['type']}'")

    def __getattr__(self, name):
        # Default all calls to the HTTP handler
        return getattr(self.http_app, name)

    @property
    def vm_hash(self) -> Optional[str]:
        """
        Returns the hash of the VM that is running this app. If the VM is not
        running in aleph.im, this will return None.
        """
        # Get hostname from environment
        hostname = socket.gethostname()

        # Add padding if necessary
        padding_length = len(hostname) % 8
        if padding_length != 0:
            hostname += "=" * (8 - padding_length)

        try:
            # Convert the hostname back to its original binary form
            item_hash_binary = base64.b32decode(hostname.upper())

            # Convert the binary form to the original vm_hash
            vm_hash = base64.b16encode(item_hash_binary).decode().lower()
        except binascii.Error:
            # If the hostname is not a valid base32 string, just return None
            return None

        return vm_hash
