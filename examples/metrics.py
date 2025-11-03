"""Server metrics upload."""
# -*- coding: utf-8 -*-

import asyncio
import os
import platform
import time
from typing import Tuple, Any, Dict

import psutil
from aleph_message.models import AlephMessage
from aleph_message.status import MessageStatus

from aleph.sdk.chains.ethereum import get_fallback_account
from aleph.sdk.client import AuthenticatedAlephHttpClient
from aleph.sdk.conf import settings


def get_sysinfo() -> Dict[str, Any]:
    uptime = int(time.time() - psutil.boot_time())
    load_avg = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)
    return {
        "uptime": uptime,
        "os": platform.platform(),
        "load_avg": load_avg,
        "num_cpus": psutil.cpu_count(),
    }


def get_memory() -> Dict[str, Any]:
    return psutil.virtual_memory()._asdict()


def get_swap_space() -> Dict[str, Any]:
    sm = psutil.swap_memory()
    return {
        "total": sm.total,
        "free": sm.free,
        "used": sm.used,
        "percent": sm.percent,
        "swapped_in": sm.sin,
        "swapped_out": sm.sout,
    }


def get_cpu() -> Dict[str, Any]:
    # interval=0 for non-blocking “since last call” percentages
    return psutil.cpu_times_percent(interval=0)._asdict()


def get_cpu_cores() -> list[Dict[str, Any]]:
    return [c._asdict() for c in psutil.cpu_times_percent(interval=0, percpu=True)]


async def send_metrics(
    session: AuthenticatedAlephHttpClient, metrics: Dict[str, Any]
) -> Tuple[AlephMessage, MessageStatus]:
    return await session.create_aggregate(
        key="metrics",
        content=metrics,
        channel="SYSINFO",
    )


def collect_metrics() -> Dict[str, Any]:
    return {
        "sysinfo": get_sysinfo(),
        "memory": get_memory(),
        "swap": get_swap_space(),
        "cpu": get_cpu(),
        "cpu_cores": get_cpu_cores(),
    }


async def main() -> None:
    account = get_fallback_account()
    async with AuthenticatedAlephHttpClient(
        account=account, api_server=settings.API_HOST
    ) as session:
        try:
            while True:
                metrics = collect_metrics()
                message, status = await send_metrics(session, metrics)
                print("sent", message.item_hash, status.value if hasattr(status, "value") else status)
                # Use non-blocking sleep in async context
                await asyncio.sleep(10)
        except asyncio.CancelledError:
            # Graceful shutdown
            pass
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    asyncio.run(main())
