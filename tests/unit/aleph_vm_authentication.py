# Keep datetime import as is as it allow patching in test
import datetime
import functools
import json
import logging
from collections.abc import Awaitable, Coroutine
from typing import Any, Callable, Dict, Literal, Union

import cryptography.exceptions
import pydantic
from aiohttp import web
from eth_account import Account
from eth_account.messages import encode_defunct
from jwcrypto import jwk
from jwcrypto.jwa import JWA
from pydantic import BaseModel, ValidationError, root_validator, validator

from aleph.sdk.utils import bytes_from_hex


logger = logging.getLogger(__name__)

DOMAIN_NAME = "localhost"


def is_token_still_valid(datestr: str) -> bool:
    """
    Checks if a token has expired based on its expiry timestamp
    """
    current_datetime = datetime.datetime.now(tz=datetime.timezone.utc)
    expiry_datetime = datetime.datetime.fromisoformat(datestr.replace("Z", "+00:00"))

    return expiry_datetime > current_datetime


def verify_wallet_signature(signature: bytes, message: str, address: str) -> bool:
    """
    Verifies a signature issued by a wallet
    """
    enc_msg = encode_defunct(hexstr=message)
    computed_address = Account.recover_message(enc_msg, signature=signature)

    return computed_address.lower() == address.lower()


class SignedPubKeyPayload(BaseModel):
    """This payload is signed by the wallet of the user to authorize an ephemeral key to act on his behalf."""

    pubkey: Dict[str, Any]
    # {'pubkey': {'alg': 'ES256', 'crv': 'P-256', 'ext': True, 'key_ops': ['verify'], 'kty': 'EC',
    #  'x': '4blJBYpltvQLFgRvLE-2H7dsMr5O0ImHkgOnjUbG2AU', 'y': '5VHnq_hUSogZBbVgsXMs0CjrVfMy4Pa3Uv2BEBqfrN4'}
    # alg: Literal["ECDSA"]
    domain: str
    address: str
    expires: str

    @property
    def json_web_key(self) -> jwk.JWK:
        """Return the ephemeral public key as Json Web Key"""

        return jwk.JWK(**self.pubkey)


class SignedPubKeyHeader(BaseModel):
    signature: bytes
    payload: bytes

    @validator("signature")
    def signature_must_be_hex(cls, value: bytes) -> bytes:
        """Convert the signature from hexadecimal to bytes"""

        return bytes_from_hex(value.decode())

    @validator("payload")
    def payload_must_be_hex(cls, value: bytes) -> bytes:
        """Convert the payload from hexadecimal to bytes"""

        return bytes_from_hex(value.decode())

    @root_validator(pre=False, skip_on_failure=True)
    def check_expiry(cls, values: Dict[str, bytes]) -> Dict[str, bytes]:
        """Check that the token has not expired"""
        payload: bytes = values["payload"]
        content = SignedPubKeyPayload.parse_raw(payload)

        if not is_token_still_valid(content.expires):
            msg = "Token expired"
            raise ValueError(msg)

        return values

    @root_validator(pre=False, skip_on_failure=True)
    def check_signature(cls, values: Dict[str, bytes]) -> Dict[str, bytes]:
        """Check that the signature is valid"""
        signature: bytes = values["signature"]
        payload: bytes = values["payload"]
        content = SignedPubKeyPayload.parse_raw(payload)

        if not verify_wallet_signature(signature, payload.hex(), content.address):
            msg = "Invalid signature"
            raise ValueError(msg)

        return values

    @property
    def content(self) -> SignedPubKeyPayload:
        """Return the content of the header"""

        return SignedPubKeyPayload.parse_raw(self.payload)


class SignedOperationPayload(BaseModel):
    time: datetime.datetime
    method: Union[Literal["POST"], Literal["GET"]]
    path: str
    # body_sha256: str  # disabled since there is no body

    @validator("time")
    def time_is_current(cls, value: datetime.datetime) -> datetime.datetime:
        """Check that the time is current and the payload is not a replay attack."""
        max_past = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(
            minutes=2
        )
        max_future = datetime.datetime.now(
            tz=datetime.timezone.utc
        ) + datetime.timedelta(minutes=2)

        if value < max_past:
            raise ValueError("Time is too far in the past")

        if value > max_future:
            raise ValueError("Time is too far in the future")

        return value


class SignedOperation(BaseModel):
    """This payload is signed by the ephemeral key authorized above."""

    signature: bytes
    payload: bytes

    @validator("signature")
    def signature_must_be_hex(cls, value: str) -> bytes:
        """Convert the signature from hexadecimal to bytes"""

        try:
            if isinstance(value, bytes):
                value = value.decode()
            return bytes_from_hex(value)

        except pydantic.ValidationError as error:
            print(value)
            logger.warning(value)

            raise error

    @validator("payload")
    def payload_must_be_hex(cls, value: bytes) -> bytes:
        """Convert the payload from hexadecimal to bytes"""

        v = bytes_from_hex(value.decode())
        _ = SignedOperationPayload.parse_raw(v)

        return v

    @property
    def content(self) -> SignedOperationPayload:
        """Return the content of the header"""
        return SignedOperationPayload.parse_raw(self.payload)


def get_signed_pubkey(request: web.Request) -> SignedPubKeyHeader:
    """Get the ephemeral public key that is signed by the wallet from the request headers."""
    signed_pubkey_header = request.headers.get("X-SignedPubKey")

    if not signed_pubkey_header:
        raise web.HTTPBadRequest(reason="Missing X-SignedPubKey header")

    try:
        return SignedPubKeyHeader.parse_raw(signed_pubkey_header)

    except KeyError as error:
        logger.debug(f"Missing X-SignedPubKey header: {error}")
        raise web.HTTPBadRequest(reason="Invalid X-SignedPubKey fields") from error

    except json.JSONDecodeError as error:
        raise web.HTTPBadRequest(reason="Invalid X-SignedPubKey format") from error

    except ValueError as errors:
        logging.debug(errors)

        for err in errors.args[0]:
            if isinstance(err.exc, json.JSONDecodeError):
                raise web.HTTPBadRequest(
                    reason="Invalid X-SignedPubKey format"
                ) from errors

            if str(err.exc) == "Token expired":
                raise web.HTTPUnauthorized(reason="Token expired") from errors

            if str(err.exc) == "Invalid signature":
                raise web.HTTPUnauthorized(reason="Invalid signature") from errors

        else:
            raise errors


def get_signed_operation(request: web.Request) -> SignedOperation:
    """Get the signed operation public key that is signed by the ephemeral key from the request headers."""
    try:
        signed_operation = request.headers["X-SignedOperation"]
        return SignedOperation.parse_raw(signed_operation)

    except KeyError as error:
        raise web.HTTPBadRequest(reason="Missing X-SignedOperation header") from error

    except json.JSONDecodeError as error:
        raise web.HTTPBadRequest(reason="Invalid X-SignedOperation format") from error

    except ValidationError as error:
        logger.debug(f"Invalid X-SignedOperation fields: {error}")
        raise web.HTTPBadRequest(reason="Invalid X-SignedOperation fields") from error


def verify_signed_operation(
    signed_operation: SignedOperation, signed_pubkey: SignedPubKeyHeader
) -> str:
    """Verify that the operation is signed by the ephemeral key authorized by the wallet."""
    pubkey = signed_pubkey.content.json_web_key

    try:
        JWA.signing_alg("ES256").verify(
            pubkey, signed_operation.payload, signed_operation.signature
        )
        logger.debug("Signature verified")

        return signed_pubkey.content.address

    except cryptography.exceptions.InvalidSignature as e:
        logger.debug("Failing to validate signature for operation", e)

        raise web.HTTPUnauthorized(reason="Signature could not verified")


async def authenticate_jwk(request: web.Request) -> str:
    """Authenticate a request using the X-SignedPubKey and X-SignedOperation headers."""
    signed_pubkey = get_signed_pubkey(request)
    signed_operation = get_signed_operation(request)

    if signed_pubkey.content.domain != DOMAIN_NAME:
        logger.debug(
            f"Invalid domain '{signed_pubkey.content.domain}' != '{DOMAIN_NAME}'"
        )
        raise web.HTTPUnauthorized(reason="Invalid domain")

    if signed_operation.content.path != request.path:
        logger.debug(
            f"Invalid path '{signed_operation.content.path}' != '{request.path}'"
        )
        raise web.HTTPUnauthorized(reason="Invalid path")

    if signed_operation.content.method != request.method:
        logger.debug(
            f"Invalid method '{signed_operation.content.method}' != '{request.method}'"
        )
        raise web.HTTPUnauthorized(reason="Invalid method")

    return verify_signed_operation(signed_operation, signed_pubkey)


async def authenticate_websocket_message(message) -> str:
    """Authenticate a websocket message since JS cannot configure headers on WebSockets."""
    signed_pubkey = SignedPubKeyHeader.parse_obj(message["X-SignedPubKey"])
    signed_operation = SignedOperation.parse_obj(message["X-SignedOperation"])

    if signed_pubkey.content.domain != DOMAIN_NAME:
        logger.debug(
            f"Invalid domain '{signed_pubkey.content.domain}' != '{DOMAIN_NAME}'"
        )
        raise web.HTTPUnauthorized(reason="Invalid domain")

    return verify_signed_operation(signed_operation, signed_pubkey)


def require_jwk_authentication(
    handler: Callable[[web.Request, str], Coroutine[Any, Any, web.StreamResponse]]
) -> Callable[[web.Request], Awaitable[web.StreamResponse]]:

    @functools.wraps(handler)
    async def wrapper(request):
        try:
            authenticated_sender: str = await authenticate_jwk(request)
        except web.HTTPException as e:
            return web.json_response(data={"error": e.reason}, status=e.status)
        except Exception as e:
            # Unexpected make sure to log it
            logging.exception(e)
            raise

        response = await handler(request, authenticated_sender)
        return response

    return wrapper
