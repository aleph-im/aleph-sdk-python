"""
Server metrics upload gateway.

This module connects to an MQTT broker, subscribes to all topics, collects
the received data into a nested dictionary structure, and periodically
uploads the collected metrics as aggregate messages to the Aleph.im network.
"""

# -*- coding: utf-8 -*-

import asyncio
import click
import logging
from typing import Dict, Any, Optional

# Dependencies for MQTT, Aleph.im client, and authentication.
import aiomqtt
from aleph.sdk.chains.common import get_fallback_private_key
from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.client import AuthenticatedAlephHttpClient
from aleph.sdk.conf import settings

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def get_input_data(value: bytes) -> Any:
    """
    Attempts to convert raw MQTT payload bytes into appropriate Python types (bool, float, or string).
    
    :param value: The raw payload as bytes.
    :return: The converted value.
    """
    if value == b"true":
        return True
    elif value == b"false":
        return False
    try:
        # Try converting to a float (common for metric values)
        return float(value)
    except ValueError:
        # Fallback to a string if float conversion fails
        return value.decode("utf-8")


# --- MQTT Callback Handlers ---

def on_disconnect(client: aiomqtt.Client, userdata: Dict[str, Any], rc: int):
    """Callback triggered on MQTT disconnection."""
    if rc != 0:
        logger.warning(f"Unexpected MQTT disconnection (RC={rc}). Will attempt auto-reconnect.")
    
    # aiomqtt (paho-based) often requires manual reconnection handling for persistent connections.
    # The main gateway loop will also attempt reconnect if no messages are received.
    client.reconnect()


def on_connect(client: aiomqtt.Client, userdata: Dict[str, Any], flags: Dict[str, Any], rc: int):
    """Callback triggered on successful MQTT connection."""
    logger.info(f"Connected to MQTT Broker with result code {rc}")

    # Subscribing to all topics upon successful connection.
    client.subscribe("/#")


def on_message(client: aiomqtt.Client, userdata: Dict[str, Any], msg: aiomqtt.MQTTMessage):
    """Callback for when a PUBLISH message is received from the server."""
    userdata["received"] = True
    state: Dict = userdata["state"]
    
    # Split the topic path (e.g., 'system/cpu/load')
    parts = msg.topic.strip("/").split("/")
    curp = state
    
    # Recursively build the nested dictionary structure from topic parts.
    for part in parts[:-1]:
        # Ensure the current part is a dictionary before traversing or initializing.
        if not isinstance(curp.get(part), dict):
            curp[part] = {}
        curp = curp[part]

    # Assign the final metric value to the innermost key.
    curp[parts[-1]] = get_input_data(msg.payload)
    logger.debug(f"Received: {parts}, Payload: {msg.payload}")


# --- Core Gateway Logic ---

async def gateway(
    host: str = "api1.aleph.im",
    port: int = 1883,
    ca_cert: Optional[str] = None,
    pkey: Optional[str] = None,
    keepalive: int = 10,
    transport: str = "tcp",
    auth: Optional[Dict[str, str]] = None,
):
    """
    Main asynchronous loop for connecting to MQTT and sending metrics to Aleph.im.
    
    This process involves: MQTT Broker -> Python Gateway -> Aleph.im Aggregate Store.
    

    :param host: MQTT Broker host.
    :param port: MQTT Broker port.
    :param ca_cert: Path to the CA Certificate file for TLS.
    :param pkey: Account private key for Aleph.im authentication.
    :param keepalive: MQTT keepalive interval.
    :param transport: MQTT transport type ('tcp' or 'websockets').
    :param auth: Dictionary containing 'username' and 'password' for MQTT basic auth.
    """
    # 1. Aleph.im Account Setup
    # Use the provided key or fall back to a default location (e.g., device.key).
    private_key = pkey if pkey else get_fallback_private_key()
    account = ETHAccount(private_key=private_key)
    
    # 2. Shared State for MQTT Callbacks and Upload Loop
    state: Dict[str, Any] = dict()
    userdata = {"account": account, "state": state, "received": False}
    
    # 3. MQTT Client Initialization
    client = aiomqtt.Client(loop=asyncio.get_event_loop(), userdata=userdata, transport=transport)
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message

    if ca_cert is not None:
        client.tls_set(ca_cert)
    if auth is not None:
        client.username_pw_set(**auth)

    # Start the non-blocking MQTT loop in the background.
    asyncio.ensure_future(client.loop_forever())

    # Connect to the broker and start receiving data.
    await client.connect(host, port, keepalive)
    logger.info("MQTT client started and connected.")

    # 4. Main Upload Loop
    while True:
        # Wait for the upload interval (10 seconds)
        await asyncio.sleep(10)
        
        # Check if any messages were received in the last interval.
        # If not, attempt reconnect to handle silent connection drops not caught by on_disconnect.
        if not userdata["received"]:
            logger.warning("No MQTT messages received recently. Attempting reconnect.")
            await client.reconnect()
            continue

        # If data was received, proceed to upload it.
        userdata["received"] = False
        
        # Use an authenticated Aleph.im session for uploading aggregate messages.
        async with AuthenticatedAlephHttpClient(
            account=account, api_server=settings.API_HOST
        ) as session:
            # Create a temporary copy of the state and clear the main state
            # immediately to allow the MQTT thread to collect new metrics
            # while the upload is ongoing (minimizing lock contention risk, 
            # though locks aren't strictly necessary in single-threaded asyncio).
            metrics_to_send = state.copy()
            state.clear() 

            for key, content in metrics_to_send.items():
                try:
                    # Upload each top-level key/value pair as a separate aggregate.
                    message, status = await session.create_aggregate(
                        key=key, content=content, channel="SYSINFO" # Changed channel to SYSINFO for clarity
                    )
                    logger.info(f"Uploaded aggregate '{key}'. Hash: {message.item_hash}")
                except Exception as e:
                    logger.error(f"Failed to upload aggregate '{key}' to Aleph.im: {e}")
                    # Re-insert failed data into state to retry later, though this
                    # risks overwriting newer data if the next message arrives quickly.
                    state[key] = content


# --- Command Line Interface ---

@click.command()
@click.option("--host", default="localhost", help="MQTT Broker host.")
@click.option("--port", default=1883, type=int, help="MQTT Broker port.")
@click.option("--user", default=None, help="MQTT Auth username.")
@click.option("--password", default=None, help="MQTT Auth password.")
@click.option("--use-tls", is_flag=True, help="Use TLS for connection.")
@click.option("--ca-cert", default=None, help="CA Cert path for TLS validation.")
@click.option(
    "--pkey",
    default=None,
    help="Account private key (optional, defaults to device.key file).",
)
def main(host: str, port: int, user: str, password: str, use_tls: bool, ca_cert: Optional[str], pkey: Optional[str]):
    """
    Runs the MQTT Gateway to Aleph.im metrics aggregator.
    """
    loop = asyncio.get_event_loop()
    auth = None
    if user is not None:
        auth = {"username": user, "password": password}

    # Automatically determine CA cert if TLS is used but no path is provided.
    if use_tls and ca_cert is None:
        try:
            import certifi
            ca_cert = certifi.where()
            logger.info(f"Using default CA Cert path from certifi: {ca_cert}")
        except ImportError:
            logger.error("TLS requested but 'certifi' is not installed and 'ca-cert' path not provided.")
            return

    loop.run_until_complete(
        gateway(host=host, port=port, ca_cert=ca_cert, pkey=pkey, auth=auth)
    )


if __name__ == "__main__":
    main()
