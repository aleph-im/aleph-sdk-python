""" Server metrics upload to the Aleph.im decentralized network. """

import asyncio
import os
import platform
import time
from typing import Dict, Any, Tuple

import psutil
from aleph_message.models import AlephMessage
from aleph_message.status import MessageStatus

from aleph.sdk.chains.ethereum import get_fallback_account
from aleph.sdk.client import AuthenticatedAlephHttpClient
from aleph.sdk.conf import settings


def get_sysinfo() -> Dict[str, Any]:
    """
    Collects basic operating system information.

    Returns:
        A dictionary containing system uptime, OS details, load averages, and CPU count.
    """
    uptime = int(time.time() - psutil.boot_time())
    sysinfo = {
        "uptime": uptime,
        "os": platform.platform(),
        "load_avg": os.getloadavg(),
        "num_cpus": psutil.cpu_count(),
    }

    return sysinfo


def get_memory() -> Dict[str, Any]:
    """
    Collects virtual memory statistics.
    Returns the psutil named tuple as a dictionary.
    """
    return psutil.virtual_memory()._asdict()


def get_swap_space() -> Dict[str, Any]:
    """
    Collects swap memory statistics.
    Returns the psutil named tuple as a dictionary, simplifying the original manual mapping.
    """
    return psutil.swap_memory()._asdict()


def get_cpu() -> Dict[str, Any]:
    """
    Collects overall CPU usage statistics (times percent).
    The '0' argument ensures non-blocking immediate measurement.
    """
    return psutil.cpu_times_percent(0)._asdict()


def get_cpu_cores() -> Dict[str, Any]:
    """
    Collects per-core CPU usage statistics (times percent).
    """
    # List comprehension to convert each named tuple for individual cores to a dictionary
    return [c._asdict() for c in psutil.cpu_times_percent(0, percpu=True)]


def collect_metrics() -> Dict[str, Any]:
    """
    Aggregates all system metrics into a single dictionary structure.
    """
    return {
        "sysinfo": get_sysinfo(),  # Added sysinfo to the main collection
        "memory": get_memory(),
        "swap": get_swap_space(),
        "cpu": get_cpu(),
        "cpu_cores": get_cpu_cores(),
    }


async def send_metrics(
    session: AuthenticatedAlephHttpClient, metrics: Dict[str, Any]
) -> Tuple[AlephMessage, MessageStatus]:
    """
    Sends the collected metrics as an AGGREGATE message to the Aleph.im network.
    The key is "metrics" and the channel is "SYSINFO".
    """
    return await session.create_aggregate(
        key="metrics", content=metrics, channel="SYSINFO"
    )


async def main():
    """
    Main asynchronous loop to collect and send metrics periodically.
    """
    # 1. Get the fallback account (used for signing the message)
    account = get_fallback_account()
    
    # 2. Initialize the asynchronous Aleph HTTP client session
    async with AuthenticatedAlephHttpClient(
        account=account, api_server=settings.API_HOST
    ) as session:
        print(f"Starting metrics upload to {settings.API_HOST}...")
        while True:
            # 3. Collect the latest system metrics
            metrics = collect_metrics()
            
            # 4. Send the metrics and await the result
            message, status = await send_metrics(session, metrics)
            
            # 5. Log the successful upload
            print(f"Successfully sent metrics. Message Hash: {message.item_hash}, Status: {status.name}")
            
            # 6. CRITICAL FIX: Use asyncio.sleep to non-blockingly wait for 10 seconds
            await asyncio.sleep(10)


if __name__ == "__main__":
    # Runs the main async function using the asyncio event loop
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nMetrics uploader stopped by user.")
