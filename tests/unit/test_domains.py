import pytest
import asyncio

from aleph.sdk.domain import AlephDNS


@pytest.mark.asyncio
async def test_url_to_domain():
    alephdns = AlephDNS()
    domain = alephdns.url_to_domain("https://aleph.im")
    query = await alephdns.query(domain, "A")
    assert query is not None
    assert len(query) > 0
    assert hasattr(query[0], "host")


@pytest.mark.asyncio
async def test_get_ipv6_adress():
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


"""
@pytest.mark.asyncio
async def test_cname():
    alephdns = AlephDNS()
    url = 'https://custom_domain_test.aleph.sh'
    check = await alephdns.custom_domain_check(url)
    assert check is not None
"""
