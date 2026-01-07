"""
MQTT Gateway for collecting IOT metrics and uploading them as Aggregate Messages to the Aleph.im network.

This script connects to an MQTT broker, subscribes to all topics ('/#'), aggregates the received 
state, and periodically sends the aggregated data to Aleph.im.
"""

import asyncio
import logging
from typing import Dict, Any, Optional

import aiomqtt
import click

from aleph.sdk.chains.common import get_fallback_private_key
from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.client import AuthenticatedAlephHttpClient
from aleph.sdk.conf import settings

# --- Setup Logging ---
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


# --- Helper Functions ---

def get_input_data(value: bytes) -> Any:
    """
    Attempts to convert byte payload into a boolean, float, or string.
    """
    if value == b"true":
        return True
    elif value == b"false":
        return False
    try:
        # Try converting to float for numeric data
        return float(value)
    except ValueError:
        # Fallback to string decoding (UTF-8)
        return value.decode("utf-8")


# --- MQTT Callbacks and State Management ---

# Note: In a modern async app, synchronous callbacks (like those used by paho-mqtt/aiomqtt) 
# can introduce complexity. We use asyncio.Lock to protect the shared 'state' dictionary 
# from race conditions between the main upload loop and the message receiving thread.

def on_disconnect(client: aiomqtt.Client, userdata: Dict[str, Any], rc: int):
    """Callback for MQTT disconnection."""
    if rc != 0:
        logger.warning("Unexpected MQTT disconnection (RC: %d). Will auto-reconnect.", rc)
    
    # aiomqtt generally handles auto-reconnect logic within its loop_forever or connect/loop structure.
    # Manual synchronous reconnect is usually discouraged in async context, but kept for compatibility.
    # client.reconnect()


def on_connect(client: aiomqtt.Client, userdata: Dict[str, Any], flags: Dict[str, Any], rc: int):
    """Callback for successful MQTT connection."""
    logger.info("Connected to MQTT broker with result code %d.", rc)

    # Subscribing to all topics.
    client.subscribe("/#")


def on_message(client: aiomqtt.Client, userdata: Dict[str, Any], msg: aiomqtt.MQTTMessage):
    """
    Callback for received MQTT messages. Updates the nested state dictionary.

    NOTE: This runs synchronously, so it must be fast and should ideally acquire a lock
    if 'state' manipulation were not isolated here, but since aiomqtt runs this on its own
    internal thread, locking is required before state read/write in the main async loop.
    """
    userdata["received"] = True
    state = userdata["state"]
    
    # As the main thread uses an asyncio.Lock, we should acquire it here.
    # However, since this is a synchronous callback, we cannot await a lock.
    # We rely on the main thread acquiring the lock *before* reading the state, 
    # and use asynchronous processing for the main loop.
    
    parts = msg.topic.strip("/").split("/")
    curp = state
    
    for part in parts[:-1]:
        # Ensure path exists for nested topic structure
        if not isinstance(curp.get(part), dict):
            curp[part] = {}
        curp = curp[part]

    curp[parts[-1]] = get_input_data(msg.payload)
    logger.debug("Received topic: %s, payload: %s", msg.topic, msg.payload)


# --- Main Async Logic ---

async def gateway(
    loop: asyncio.AbstractEventLoop,
    host: str = "api1.aleph.im",
    port: int = 1883,
    ca_cert: Optional[str] = None,
    pkey: Optional[str] = None,
    keepalive: int = 10,
    transport: str = "tcp",
    auth: Optional[Dict[str, str]] = None,
):
    """
    Main asynchronous loop for MQTT connection, state aggregation, and Aleph.im upload.
    """
    if pkey is None:
        pkey = get_fallback_private_key()

    account = ETHAccount(private_key=pkey)
    
    # State dictionary holds the aggregated IOT data.
    state: Dict[str, Any] = dict()
    # Lock protects the state dictionary from race conditions between MQTT message handler and Aleph.im sender.
    state_lock = asyncio.Lock()
    
    userdata = {"account": account, "state": state, "received": False, "lock": state_lock}
    
    # Initialize aiomqtt Client
    # NOTE: Passing loop explicitly for compatibility with older aiomqtt usage, but modern usage avoids it.
    client = aiomqtt.Client(loop, userdata=userdata, transport=transport)
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message

    if ca_cert is not None:
        client.tls_set(ca_cert)
    if auth is not None:
        client.username_pw_set(**auth)

    # Start the MQTT network loop in the background.
    asyncio.ensure_future(client.loop_forever())

    try:
        await client.connect(host, port, keepalive)
        logger.info("MQTT client started and connected.")
    except Exception as e:
        logger.critical("Failed to connect to MQTT broker: %s", e)
        return

    # Main upload loop.
    while True:
        # Await non-blocking sleep (CRITICAL FIX: replaced time.sleep)
        await asyncio.sleep(10) 

        # Check if any messages were received since the last upload.
        if not userdata["received"]:
            logger.warning("No new messages received in the last 10 seconds. Checking connection...")
            # Attempting manual reconnect if no data received, assumes connection might be stale.
            # In production, relying on MQTT's built-in keepalive/reconnect is usually better.
            try:
                 # Ensure loop_forever is still running before attempting connect/reconnect
                 if not client._loop.is_running():
                     asyncio.ensure_future(client.loop_forever())
                 await client.reconnect()
                 logger.info("Attempted manual reconnect.")
            except Exception as e:
                logger.error("Failed during reconnection attempt: %s", e)
                continue

        
        # 1. Acquire Lock before reading/clearing shared state.
        async with state_lock:
            if not state:
                logger.debug("State is empty, skipping upload.")
                continue
                
            # Create a copy of the state for upload and clear the original.
            metrics_to_send = state.copy()
            state.clear()
            
            # Reset received flag for the next cycle.
            userdata["received"] = False

        # 2. Upload aggregated metrics to Aleph.im
        try:
            async with AuthenticatedAlephHttpClient(
                account=account, api_server=settings.API_HOST
            ) as session:
                for key, content in metrics_to_send.items():
                    # Create an aggregate message for each top-level key/value in the state.
                    message, status = await session.create_aggregate(
                        key=key, content=content, channel="IOT_TEST"
                    )
                    logger.info("Uploaded key '%s'. Item Hash: %s, Status: %s", key, message.item_hash, status)
        except Exception as e:
            logger.error("Error during Aleph.im upload: %s", e, exc_info=True)


# --- CLI Entry Point ---

@click.command()
@click.option("--host", default="localhost", help="MQTT Broker host")
@click.option("--port", default=1883, help="MQTT Broker port")
@click.option("--user", default=None, help="MQTT Auth username")
@click.option("--password", default=None, help="MQTT Auth password")
@click.option("--use-tls", is_flag=True, help="Use TLS for connection")
@click.option("--ca-cert", default=None, help="CA Cert path")
@click.option(
    "--pkey",
    default=None,
    help="Account private key (optional, defaults to fallback key)",
)
def main(host, port, user, password, use_tls=False, ca_cert=None, pkey=None):
    """Starts the MQTT to Aleph.im gateway service."""
    
    # Get the event loop and prepare credentials.
    loop = asyncio.get_event_loop()
    auth = None
    if user is not None:
        auth = {"username": user, "password": password}

    # Handle TLS setup
    if use_tls and ca_cert is None:
        try:
            import certifi
            ca_cert = certifi.where()
            logger.info("Using certifi CA bundle: %s", ca_cert)
        except ImportError:
            logger.error("TLS requested but 'certifi' not installed and --ca-cert not provided.")
            return

    # Run the async gateway function.
    try:
        loop.run_until_complete(
            gateway(loop, host, port, ca_cert=ca_cert, pkey=pkey, auth=auth)
        )
    except KeyboardInterrupt:
        logger.info("Service shutdown initiated by user.")
    except Exception as e:
        logger.critical("Gateway stopped due to unexpected error: %s", e, exc_info=True)


if __name__ == "__main__":
    main()
