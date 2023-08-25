import pytest
import asyncio

from aleph.sdk.domain import AlephDNS
from aleph.sdk.exceptions import DomainConfigurationError


@pytest.mark.asyncio
async def test_url_to_domain():
    alephdns = AlephDNS()
    domain = alephdns.url_to_domain("https://aleph.im")
    query = await alephdns.query(domain, "A")
    assert query is not None
    assert len(query) > 0
    assert hasattr(query[0], "host")


@pytest.mark.asyncio
async def test_get_ipv6_address():
    alephdns = AlephDNS()
    url = "https://aleph.im"
    ipv6_address = await alephdns.get_ipv6_address(url)
    assert ipv6_address is not None
    assert len(ipv6_address) > 0
    assert ":" in ipv6_address[0]


@pytest.mark.asyncio
async def test_dnslink():
    alephdns = AlephDNS()
    url = "https://aleph.im"
    dnslink = await alephdns.get_dnslink(url)
    assert dnslink is not None


@pytest.mark.asyncio
async def test_configured_domain():
    alephdns = AlephDNS()
    url = 'https://custom-domain-unit-test.aleph.sh'
    status = await alephdns.check_domain(url, "ipfs", "0xfakeaddress")
    assert type(status) is dict


@pytest.mark.asyncio
async def test_not_configured_domain():
    alephdns = AlephDNS()
    url = 'https://not-configured-domain.aleph.sh'
    with pytest.raises(DomainConfigurationError):
        status = await alephdns.check_domain(url, "ipfs", "0xfakeaddress")

