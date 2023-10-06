import asyncio
from typing import Awaitable, Callable, TypeVar

T = TypeVar("T")


def wrap_async(func: Callable[..., Awaitable[T]]) -> Callable[..., T]:
    """Wrap an asynchronous function into a synchronous one,
    for easy use in synchronous code.
    """

    def func_caller(*args, **kwargs):
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(func(*args, **kwargs))

    # Copy wrapped function interface:
    func_caller.__doc__ = func.__doc__
    func_caller.__annotations__ = func.__annotations__
    func_caller.__defaults__ = func.__defaults__
    func_caller.__kwdefaults__ = func.__kwdefaults__
    return func_caller
