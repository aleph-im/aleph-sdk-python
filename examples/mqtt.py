# optimized_metrics_upload.py

"""
Server metrics upload via MQTT gateway to Aleph.im network.
Uses aiomqtt (Asyncio native) for clean, non-blocking operation.
"""

import asyncio
import json
from typing import Dict, Union, Any, List

import aiomqtt
import click
from httpx import HTTPStatusError

from aleph.sdk.chains.common import get_fallback_private_key
from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.client import AuthenticatedAlephHttpClient
from aleph.sdk.conf import settings

# Define the metric container structure
MetricsDict = Dict[str, Any]
# Consistent channel for metric aggregates
METRICS_CHANNEL = "SYSINFO"
# Message topic to subscribe to
MQTT_TOPIC = "/#"


def _decode_payload(value: bytes) -> Union[bool, float, str]:
    """
    Decodes the MQTT payload (bytes) into the appropriate Python type (bool, float, or string).
    """
    if value == b"true":
        return True
    elif value == b"false":
        return False
    try:
        # Try to decode as a float (for numeric metrics)
        return float(value)
    except ValueError:
        # Fallback to UTF-8 string (for labels or non-numeric metrics)
        return value.decode("utf-8")


def _update_metrics_state(state: MetricsDict, topic: str, payload: bytes):
    """
    Parses the MQTT topic and dynamically updates the nested metrics dictionary.
    Example: topic 'host/cpu/usage' sets state['host']['cpu']['usage'].
    """
    parts: List[str] = topic.strip("/").split("/")
    curp: MetricsDict = state
    
    # Iterate through topic parts to build nested structure, excluding the final key
    for part in parts[:-1]:
        if not isinstance(curp.get(part), dict):
            curp[part] = {}
        curp = curp[part]
    
    # Set the final metric value
    curp[parts[-1]] = _decode_payload(payload)
    print(f"Received: {parts}, Value: {curp[parts[-1]]}")


async def _send_metrics(account: ETHAccount, metrics: MetricsDict):
    """
    Authenticates and sends the collected metrics as a single aggregate message to Aleph.im.
    """
    async with AuthenticatedAlephHttpClient(
        account=account, api_server=settings.API_HOST
    ) as session:
        # Send all collected metrics under the single 'metrics' key
        message, _ = await session.create_aggregate(
            key="metrics", content=metrics, channel=METRICS_CHANNEL
        )
        print(f"Sent aggregate message: {message.item_hash}")


async def gateway(
    host: str,
    port: int,
    ca_cert: Optional[str] = None,
    pkey: Optional[str] = None,
    auth: Optional[Dict[str, str]] = None,
    send_interval: int = 10,
):
    """
    Connects to the MQTT broker, listens for metrics, and periodically uploads them to Aleph.im.
    """
    # 1. Initialize Aleph Account
    if pkey is None:
        pkey = get_fallback_private_key()

    account = ETHAccount(private_key=pkey)
    
    # Use a single dictionary to hold all collected metrics
    state: MetricsDict = dict()
    
    # Determine the transport type based on TLS usage
    transport = "websockets" if port == 443 else "tcp"
    
    # 2. Connect to MQTT Broker and process messages
    try:
        # Use aiomqtt's async context manager for robust connection management and auto-reconnect
        async with aiomqtt.Client(hostname=host, port=port, transport=transport, **(auth or {})) as client:
            
            # Subscribe to all topics immediately after connection
            await client.subscribe(MQTT_TOPIC)
            print(f"Connected to MQTT broker {host}:{port}. Subscribed to {MQTT_TOPIC}")

            # Use a separate task for sending metrics to run alongside message listening
            send_task = asyncio.create_task(
                _periodic_sender(account, state, send_interval)
            )

            # Process incoming messages asynchronously
            async for message in client.messages:
                # Update the shared metrics state upon receiving a message
                _update_metrics_state(state, message.topic.value, message.payload)

    except aiomqtt.MqttError as e:
        print(f"MQTT Error: {e}. Retrying connection in 5 seconds.")
        # Introduce a delay before allowing the main loop to attempt reconnection
        await asyncio.sleep(5)
    except HTTPStatusError as e:
        print(f"Aleph API Error during upload: {e}")
        # Continue listening, hoping the API recovers
    finally:
        if 'send_task' in locals() and not send_task.done():
            send_task.cancel()


async def _periodic_sender(account: ETHAccount, state: MetricsDict, interval: int):
    """
    Periodically checks the state and uploads metrics to Aleph.im.
    """
    while True:
        try:
            # Wait for the next interval
            await asyncio.sleep(interval)
            
            # Only upload if some metrics have been collected
            if state:
                await _send_metrics(account, state)
            else:
                print("Waiting for initial metrics...")

        except asyncio.CancelledError:
            # Graceful exit upon task cancellation
            print("Sender task cancelled.")
            break
        except Exception as e:
            # Catch all exceptions to keep the sender running
            print(f"An unexpected error occurred in sender task: {e}")


@click.command()
@click.option("--host", default="api1.aleph.im", help="MQTT Broker host")
@click.option("--port", default=8883, type=int, help="MQTT Broker port (Default 8883 for TLS/Websockets)")
@click.option("--user", default=None, help="MQTT Auth username")
@click.option("--password", default=None, help="MQTT Auth password")
@click.option("--use-tls", is_flag=True, help="Use TLS/SSL for connection")
@click.option("--ca-cert", default=None, help="Path to CA Cert file")
@click.option("--pkey", default=None, help="Account private key")
@click.option("--interval", default=10, type=int, help="Interval in seconds for metric uploads")
def main(host, port, user, password, use_tls=False, ca_cert=None, pkey=None, interval=10):
    """
    Starts the MQTT-to-Aleph.im metric gateway.
    """
    # 1. Setup Auth
    auth = {"username": user, "password": password} if user is not None else None

    # 2. Handle TLS/Cert setup
    if use_tls and ca_cert is None:
        import certifi
        ca_cert = certifi.where()
        print(f"Using default CA bundle from certifi: {ca_cert}")

    # 3. Run the async gateway
    try:
        asyncio.run(
            gateway(host, port, ca_cert=ca_cert, pkey=pkey, auth=auth, send_interval=interval)
        )
    except KeyboardInterrupt:
        print("\nGateway stopped by user.")
    except Exception as e:
        print(f"Fatal error in main execution: {e}")


if __name__ == "__main__":
    main()
