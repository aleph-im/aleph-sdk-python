""" Server metrics upload.
"""

# -*- coding: utf-8 -*-

import click
from aiohttp import web

from aleph.sdk.chains.common import get_fallback_private_key
from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.client import AuthenticatedAlephHttpClient

app = web.Application()
routes = web.RouteTableDef()


@routes.get("/")
async def hello(request):
    return web.Response(text="Hello, world")


@routes.post("/p/{source}")
async def source_post(request):
    # print(await request.text())
    data = await request.post()
    data = dict(data.copy().items())

    secret = data.pop("secret", None)
    data["source"] = request.match_info["source"]

    if app["secret"] is not None:
        if secret != app["secret"]:
            return web.json_response(
                {"status": "error", "message": "unauthorized secret"}
            )
    async with AuthenticatedAlephHttpClient(
        account=app["account"], api_server="https://api2.aleph.im"
    ) as session:
        message, _status = await session.create_post(
            post_content=data,
            post_type="event",
            channel=app["channel"],
        )

    return web.json_response({"status": "success", "item_hash": message.item_hash})


@click.command()
@click.option("--host", default="localhost", help="http host")
@click.option("--port", default=80, help="http port")
@click.option("--channel", default="GATEWAY", help="Channel for data post")
@click.option(
    "--pkey",
    default=None,
    help="Account private key (optionnal, will default to device.key file)",
)
@click.option("--secret", default=None, help="Needed secret to be allowed to post")
def main(host, port, channel, pkey=None, secret=None):
    app.add_routes(routes)

    app["secret"] = secret
    app["channel"] = channel

    if pkey is None:
        pkey = get_fallback_private_key()

    account = ETHAccount(private_key=pkey)
    app["account"] = account

    web.run_app(app, host=host, port=port)


if __name__ == "__main__":
    main()
