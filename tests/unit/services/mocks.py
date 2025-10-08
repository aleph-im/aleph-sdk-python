from unittest.mock import AsyncMock, MagicMock

import pytest

from ..conftest import make_custom_mock_response

FAKE_CRN_GPU_HASH = "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabca"
FAKE_CRN_GPU_ADDRESS = "0xBCABCABCABCABCABCABCABCABCABCABCABCABCAB"
FAKE_CRN_GPU_URL = "https://test.gpu.crn.com"

FAKE_CRN_CONF_HASH = "defdefdefdefdefdefdefdefdefdefdefdefdefdefdefdefdefdefdefdefdefd"
FAKE_CRN_CONF_ADDRESS = "0xDEfDEfDEfDEfDEfDEfDEfDEfDEfDEfDEfDEfDEfDEf"
FAKE_CRN_CONF_URL = "https://test.conf.crn"

FAKE_CRN_BASIC_HASH = "aaaabbbbccccddddeeeeffff1111222233334444555566667777888899990000"
FAKE_CRN_BASIC_ADDRESS = "0xAAAABBBBCCCCDDDDEEEEFFFF1111222233334444"
FAKE_CRN_BASIC_URL = "https://test.basic.crn.com"


@pytest.fixture
def vm_status_v2():
    return {
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": {
            "networking": {
                "ipv4_network": "192.168.0.0/24",
                "host_ipv4": "192.168.0.1",
                "ipv6_network": "2001:db8::/64",
                "ipv6_ip": "2001:db8::1",
                "mapped_ports": {},
            },
            "status": {
                "defined_at": "2023-01-01T00:00:00Z",
                "started_at": "2023-01-01T00:00:00Z",
                "preparing_at": "2023-01-01T00:00:00Z",
                "prepared_at": "2023-01-01T00:00:00Z",
                "starting_at": "2023-01-01T00:00:00Z",
                "stopping_at": "2023-01-01T00:00:00Z",
                "stopped_at": "2023-01-01T00:00:00Z",
            },
            "running": True,
        }
    }


@pytest.fixture
def vm_status_v1():
    return {
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": {
            "networking": {"ipv4": "192.168.0.1", "ipv6": "2001:db8::1"}
        }
    }


@pytest.fixture
def mock_crn_list():
    """Create a mock CRN list for testing."""
    return [
        {
            "hash": FAKE_CRN_GPU_HASH,
            "name": "Test GPU Instance",
            "time": 1739525120.505,
            "type": "compute",
            "owner": FAKE_CRN_GPU_ADDRESS,
            "score": 0.964502797686815,
            "banner": "",
            "locked": True,
            "parent": FAKE_CRN_GPU_HASH,
            "reward": FAKE_CRN_GPU_ADDRESS,
            "status": "linked",
            "address": FAKE_CRN_GPU_URL,
            "manager": "",
            "picture": "",
            "authorized": "",
            "description": "",
            "performance": 0,
            "multiaddress": "",
            "score_updated": True,
            "stream_reward": FAKE_CRN_GPU_ADDRESS,
            "inactive_since": None,
            "decentralization": 0.852680607762069,
            "registration_url": "",
            "terms_and_conditions": "",
            "config_from_crn": True,
            "debug_config_from_crn_at": "2025-06-18T12:09:03.843059+00:00",
            "debug_config_from_crn_error": "None",
            "debug_usage_from_crn_at": "2025-06-18T12:09:03.843059+00:00",
            "usage_from_crn_error": "None",
            "version": "1.6.0-rc1",
            "payment_receiver_address": FAKE_CRN_GPU_ADDRESS,
            "gpu_support": True,
            "confidential_support": False,
            "qemu_support": True,
            "system_usage": {
                "cpu": {
                    "count": 20,
                    "load_average": {
                        "load1": 0.357421875,
                        "load5": 0.31982421875,
                        "load15": 0.34912109375,
                    },
                    "core_frequencies": {"min": 800, "max": 4280},
                },
                "mem": {"total_kB": 67219530, "available_kB": 61972037},
                "disk": {"total_kB": 1853812338, "available_kB": 1320664518},
                "period": {
                    "start_timestamp": "2025-06-18T12:09:00Z",
                    "duration_seconds": 60,
                },
                "properties": {
                    "cpu": {
                        "architecture": "x86_64",
                        "vendor": "GenuineIntel",
                        "features": [],
                    }
                },
                "gpu": {
                    "devices": [
                        {
                            "vendor": "NVIDIA",
                            "model": "RTX 4000 ADA",
                            "device_name": "AD104GL [RTX 4000 SFF Ada Generation]",
                            "device_class": "0300",
                            "pci_host": "01:00.0",
                            "device_id": "10de:27b0",
                            "compatible": True,
                        }
                    ],
                    "available_devices": [
                        {
                            "vendor": "NVIDIA",
                            "model": "RTX 4000 ADA",
                            "device_name": "AD104GL [RTX 4000 SFF Ada Generation]",
                            "device_class": "0300",
                            "pci_host": "01:00.0",
                            "device_id": "10de:27b0",
                            "compatible": True,
                        }
                    ],
                },
                "active": True,
            },
            "compatible_gpus": [
                {
                    "vendor": "NVIDIA",
                    "model": "RTX 4000 ADA",
                    "device_name": "AD104GL [RTX 4000 SFF Ada Generation]",
                    "device_class": "0300",
                    "pci_host": "01:00.0",
                    "device_id": "10de:27b0",
                    "compatible": True,
                }
            ],
            "compatible_available_gpus": [
                {
                    "vendor": "NVIDIA",
                    "model": "RTX 4000 ADA",
                    "device_name": "AD104GL [RTX 4000 SFF Ada Generation]",
                    "device_class": "0300",
                    "pci_host": "01:00.0",
                    "device_id": "10de:27b0",
                    "compatible": True,
                }
            ],
            "ipv6_check": {"host": True, "vm": True},
        },
        {
            "hash": FAKE_CRN_CONF_HASH,
            "name": "Test Conf CRN",
            "time": 1739296606.021,
            "type": "compute",
            "owner": FAKE_CRN_CONF_ADDRESS,
            "score": 0.964334395009276,
            "banner": "",
            "locked": False,
            "parent": FAKE_CRN_CONF_HASH,
            "reward": FAKE_CRN_CONF_ADDRESS,
            "status": "linked",
            "address": FAKE_CRN_CONF_URL,
            "manager": "",
            "picture": "",
            "authorized": "",
            "description": "",
            "performance": 0,
            "multiaddress": "",
            "score_updated": False,
            "stream_reward": FAKE_CRN_CONF_ADDRESS,
            "inactive_since": None,
            "decentralization": 0.994724704221032,
            "registration_url": "",
            "terms_and_conditions": "",
            "config_from_crn": False,
            "debug_config_from_crn_at": "2025-06-18T12:09:03.951298+00:00",
            "debug_config_from_crn_error": "None",
            "debug_usage_from_crn_at": "2025-06-18T12:09:03.951298+00:00",
            "usage_from_crn_error": "None",
            "version": "1.5.1",
            "payment_receiver_address": FAKE_CRN_CONF_ADDRESS,
            "gpu_support": False,
            "confidential_support": True,
            "qemu_support": True,
            "system_usage": {
                "cpu": {
                    "count": 224,
                    "load_average": {
                        "load1": 3.8466796875,
                        "load5": 3.9228515625,
                        "load15": 3.82080078125,
                    },
                    "core_frequencies": {"min": 1500, "max": 2200},
                },
                "mem": {"total_kB": 807728145, "available_kB": 630166945},
                "disk": {"total_kB": 14971880235, "available_kB": 152975388},
                "period": {
                    "start_timestamp": "2025-06-18T12:09:00Z",
                    "duration_seconds": 60,
                },
                "properties": {
                    "cpu": {
                        "architecture": "x86_64",
                        "vendor": "AuthenticAMD",
                        "features": ["sev", "sev_es"],
                    }
                },
                "gpu": {"devices": [], "available_devices": []},
                "active": True,
            },
            "compatible_gpus": [],
            "compatible_available_gpus": [],
            "ipv6_check": {"host": True, "vm": True},
        },
        {
            "hash": FAKE_CRN_BASIC_HASH,
            "name": "Test Basic CRN",
            "time": 1687179700.242,
            "type": "compute",
            "owner": FAKE_CRN_BASIC_ADDRESS,
            "score": 0.979808976368904,
            "banner": FAKE_CRN_BASIC_HASH,
            "locked": False,
            "parent": FAKE_CRN_BASIC_HASH,
            "reward": FAKE_CRN_BASIC_ADDRESS,
            "status": "linked",
            "address": FAKE_CRN_BASIC_URL,
            "manager": FAKE_CRN_BASIC_ADDRESS,
            "picture": FAKE_CRN_BASIC_HASH,
            "authorized": "",
            "description": "",
            "performance": 0,
            "multiaddress": "",
            "score_updated": True,
            "stream_reward": FAKE_CRN_BASIC_ADDRESS,
            "inactive_since": None,
            "decentralization": 0.93953628188216,
            "registration_url": "",
            "terms_and_conditions": "",
            "config_from_crn": True,
            "debug_config_from_crn_at": "2025-06-18T12:08:59.599676+00:00",
            "debug_config_from_crn_error": "None",
            "debug_usage_from_crn_at": "2025-06-18T12:08:59.599676+00:00",
            "usage_from_crn_error": "None",
            "version": "1.5.1",
            "payment_receiver_address": FAKE_CRN_BASIC_ADDRESS,
            "gpu_support": False,
            "confidential_support": False,
            "qemu_support": True,
            "system_usage": {
                "cpu": {
                    "count": 32,
                    "load_average": {"load1": 0, "load5": 0.01513671875, "load15": 0},
                    "core_frequencies": {"min": 1200, "max": 3400},
                },
                "mem": {"total_kB": 270358832, "available_kB": 266152607},
                "disk": {"total_kB": 1005067972, "available_kB": 919488466},
                "period": {
                    "start_timestamp": "2025-06-18T12:09:00Z",
                    "duration_seconds": 60,
                },
                "properties": {
                    "cpu": {
                        "architecture": "x86_64",
                        "vendor": "GenuineIntel",
                        "features": [],
                    }
                },
                "gpu": {"devices": [], "available_devices": []},
                "active": True,
            },
            "compatible_gpus": [],
            "compatible_available_gpus": [],
            "ipv6_check": {"host": True, "vm": False},
        },
    ]


def make_mock_aiohttp_session(mocked_json_response):
    mock_response = AsyncMock()
    mock_response.json.return_value = mocked_json_response
    mock_response.raise_for_status.return_value = None

    session = MagicMock()

    session_cm = AsyncMock()
    session_cm.__aenter__.return_value = session

    get_cm = AsyncMock()
    get_cm.__aenter__.return_value = mock_response

    post_cm = AsyncMock()
    post_cm.__aenter__.return_value = mock_response

    session.get = MagicMock(return_value=get_cm)
    session.post = MagicMock(return_value=post_cm)

    return session_cm


def make_mock_get_active_vms_parametrized(v2_fails, expected_payload):
    session = MagicMock()

    def get(url, *args, **kwargs):
        mock_resp = None
        if "/v2/about/executions/list" in url and v2_fails:
            mock_resp = make_custom_mock_response(expected_payload, 404)
        else:
            mock_resp = make_custom_mock_response(expected_payload)

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__.return_value = mock_resp
        return mock_ctx

    def post(url, *args, **kwargs):
        if "/update" in url:
            return make_custom_mock_response(
                {"status": "ok", "msg": "VM not starting yet"}, 200
            )
        return None

    session.get = MagicMock(side_effect=get)

    session.post = MagicMock(side_effect=post)

    session_cm = AsyncMock()
    session_cm.__aenter__.return_value = session

    return session_cm
