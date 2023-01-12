import asyncio

import aiohttp

from aleph_client.types import Account


class UserSession:
    api_server: str
    http_session: aiohttp.ClientSession

    def __init__(self, api_server: str):
        self.api_server = api_server
        self.http_session = aiohttp.ClientSession(base_url=api_server)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        close_fut = self.http_session.close()
        try:
            loop = asyncio.get_running_loop()
            loop.run_until_complete(close_fut)
        except RuntimeError:
            asyncio.run(close_fut)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.http_session.close()


class AuthenticatedUserSession(UserSession):
    account: Account

    def __init__(self, account: Account, api_server: str):
        super().__init__(api_server=api_server)
        self.account = account
