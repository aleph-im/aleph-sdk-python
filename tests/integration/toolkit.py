import asyncio
import time
from typing import Awaitable, Callable, TypeVar

from aleph.sdk.models.message import MessagesResponse

T = TypeVar("T")


async def try_until(
    coroutine: Callable[..., Awaitable[T]],
    condition: Callable[[T], bool],
    timeout: float,
    time_between_attempts: float = 1,
    *args,
    **kwargs,
) -> T:
    start_time = time.monotonic()

    while time.monotonic() < start_time + timeout:
        result = await coroutine(*args, **kwargs)
        if condition(result):
            return result

        await asyncio.sleep(time_between_attempts)
    else:
        raise TimeoutError(f"No success in {timeout} seconds.")


def has_messages(response: MessagesResponse) -> bool:
    return len(response.messages) > 0


def has_no_messages(response: MessagesResponse) -> bool:
    return len(response.messages) == 0
