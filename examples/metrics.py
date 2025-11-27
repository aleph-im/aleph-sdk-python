"""
Server metrics collection and asynchronous upload to the Aleph.im network 
using an Aggregate Message.
"""

import asyncio
import os
import platform
import time
import logging
from typing import Tuple, Dict, Any

import psutil
from aleph_message.models import AlephMessage
from aleph_message.status import MessageStatus

from aleph.sdk.chains.ethereum import get_fallback_account
from aleph.sdk.client import AuthenticatedAlephHttpClient
from aleph.sdk.conf import settings

# --- Setup Logging ---
# Configure basic logging to replace direct 'print' statements.
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


# --- Metrics Collection Functions ---

def get_sysinfo() -> Dict[str, Any]:
    """
    Collects basic system information: uptime, OS, load averages, and CPU count.
    """
    uptime = int(time.time() - psutil.boot_time())
    return {
        "uptime": uptime,
        "os": platform.platform(),
        # Get load average, which is usually a tuple of 1, 5, and 15-minute averages.
        "load_avg": os.getloadavg(),
        "num_cpus": psutil.cpu_count(),
    }


def get_memory() -> Dict[str, Any]:
    """
    Collects virtual memory statistics.
    """
    # psutil returns a named tuple, converted to dict for JSON serialization.
    return psutil.virtual_memory()._asdict()


def get_swap_space() -> Dict[str, Any]:
    """
    Collects swap space usage and performance statistics.
    """
    sm = psutil.swap_memory()
    # Explicitly map the required fields from the named tuple for clarity.
    return {
        "total": sm.total,
        "free": sm.free,
        "used": sm.used,
        "percent": sm.percent,
        "swapped_in": sm.sin,  # bytes swapped in
        "swapped_out": sm.sout, # bytes swapped out
    }


def get_cpu() -> Dict[str, Any]:
    """
    Collects overall CPU utilization percentages.

    NOTE: Using interval=1 second to ensure accurate CPU *utilization* percentage
    since the last call, instead of raw absolute counter values.
    """
    return psutil.cpu_times_percent(interval=1)._asdict()


def get_cpu_cores() -> list[Dict[str, Any]]:
    """
    Collects per-CPU core utilization percentages.
    
    NOTE: Using interval=1 second for accurate percentage calculation.
    """
    # interval=1 is required here as well for per-core utilization percentage.
    return [c._asdict() for c in psutil.cpu_times_percent(interval=1, percpu=True)]


def collect_metrics() -> Dict[str, Any]:
    """
    Aggregates all system metrics into a single dictionary.
    """
    # Note: get_sysinfo() is static and might only need to be called once,
    # but including it here for completeness.
    return {
        "sysinfo": get_sysinfo(),
        "memory": get_memory(),
        "swap": get_swap_space(),
        "cpu": get_cpu(),
        "cpu_cores": get_cpu_cores(),
    }


# --- Aleph.im Communication ---

async def send_metrics(
    session: AuthenticatedAlephHttpClient, metrics: Dict[str, Any]
) -> Tuple[AlephMessage, MessageStatus]:
    """
    Sends the collected metrics as an Aggregate message to the Aleph.im network.
    """
    logger.info("Sending metrics to Aleph.im...")
    return await session.create_aggregate(
        key="metrics", 
        content=metrics, 
        channel="SYSINFO"
    )


# --- Main Execution Loop ---

async def main():
    """
    The main asynchronous loop for collecting and uploading metrics.
    """
    # Initialize the account using a fallback mechanism defined in the SDK.
    account = get_fallback_account()
    
    # Use AuthenticatedAlephHttpClient as an async context manager for safe session handling.
    async with AuthenticatedAlephHttpClient(
        account=account, api_server=settings.API_HOST
    ) as session:
        while True:
            try:
                # Collect the latest metrics.
                metrics = collect_metrics()
                
                # Send metrics asynchronously.
                message, status = await send_metrics(session, metrics)
                
                logger.info("Metrics sent successfully.")
                logger.debug("Item Hash: %s, Status: %s", message.item_hash, status)
                
            except Exception as e:
                # Log any exception encountered during collection or upload.
                logger.error("Error during metrics collection or sending: %s", e, exc_info=True)
                
            # Correct use of asyncio.sleep to non-blocking wait in an async loop.
            await asyncio.sleep(10)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Service stopped by user (KeyboardInterrupt).")
    except Exception as e:
        logger.critical("Critical error in main execution: %s", e, exc_info=True)
