""" Server metrics upload.
"""

import asyncio
import os
import platform
import time
from typing import Tuple, Dict, Any, List

import psutil
from aleph_message.models import AlephMessage
from aleph_message.status import MessageStatus

from aleph.sdk.chains.ethereum import get_fallback_account
from aleph.sdk.client import AuthenticatedAlephHttpClient
from aleph.sdk.conf import settings

# --- Constants for Aleph.im Message ---
METRICS_KEY = "metrics"
METRICS_CHANNEL = "SYSINFO"
# ---

def get_sysinfo() -> Dict[str, Any]:
    """Collects general system information."""
    uptime = int(time.time() - psutil.boot_time())
    # os.getloadavg() is standard on Unix-like systems, may raise OSError on Windows
    try:
        load_avg = os.getloadavg()
    except OSError:
        load_avg = None

    sysinfo = {
        "uptime": uptime,
        "os": platform.platform(),
        "load_avg": load_avg,
        "num_cpus": psutil.cpu_count(),
    }
    return sysinfo


def get_memory() -> Dict[str, int]:
    """Collects virtual memory statistics."""
    # psutil returns a named tuple; converting to dict for consistency is cleaner
    return psutil.virtual_memory()._asdict()


def get_swap_space() -> Dict[str, Any]:
    """Collects swap memory statistics."""
    sm = psutil.swap_memory()
    swap = {
        "total": sm.total,
        "free": sm.free,
        "used": sm.used,
        "percent": sm.percent,
        "swapped_in": sm.sin,
        "swapped_out": sm.sout,
    }
    return swap


def get_cpu() -> Dict[str, float]:
    """Collects aggregate CPU time percentages (non-blocking)."""
    # Interval 0 means non-blocking, returning instantaneous values since last call.
    return psutil.cpu_times_percent(interval=0)._asdict()


def get_cpu_cores() -> List[Dict[str, float]]:
    """Collects CPU time percentages per core (non-blocking)."""
    # interval=0 and percpu=True returns a list of dicts for each core.
    return [c._asdict() for c in psutil.cpu_times_percent(interval=0, percpu=True)]


async def send_metrics(
    session: AuthenticatedAlephHttpClient, metrics: Dict[str, Any]
) -> Tuple[AlephMessage, MessageStatus]:
    """Sends collected metrics as an aggregate message to the Aleph.im network."""
    return await session.create_aggregate(
        key=METRICS_KEY, 
        content=metrics, 
        channel=METRICS_CHANNEL
    )


def collect_metrics() -> Dict[str, Any]:
    """Gathers all system metrics into a single dictionary."""
    return {
        # FIX: Include system info metadata
        "sysinfo": get_sysinfo(), 
        "memory": get_memory(),
        "swap": get_swap_space(),
        "cpu": get_cpu(),
        "cpu_cores": get_cpu_cores(),
    }


async def main():
    """Main asynchronous loop to collect and upload metrics periodically."""
    # Aleph SDK automatically finds the private key (fallback account)
    account = get_fallback_account()
    
    # Use AuthenticatedAlephHttpClient context manager for session management
    async with AuthenticatedAlephHttpClient(
        account=account, 
        api_server=settings.API_HOST
    ) as session:
        log.info("Starting Aleph.im metrics uploader...")
        while True:
            try:
                metrics = collect_metrics()
                
                # Send the data to the decentralized network
                message, status = await send_metrics(session, metrics)
                
                log.info(f"Sent aggregate metrics. Item Hash: {message.item_hash}, Status: {status}")
            
            except Exception as e:
                # Log non-fatal errors (e.g., temporary network failure) and continue
                log.error(f"Error sending metrics to Aleph.im: {e}")

            # CRITICAL FIX: Use non-blocking asyncio.sleep() inside the async loop
            await asyncio.sleep(10)


if __name__ == "__main__":
    # Configure logging before running the asynchronous loop
    import logging as log
    log.basicConfig(level=log.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Metrics uploader stopped by user.")
    except Exception as e:
        log.critical(f"Fatal error in main loop: {e}")
