import pytest

from aleph.sdk.domain import DomainValidator, TargetType, hostname_from_url
from aleph.sdk.exceptions import DomainConfigurationError


def test_hostname():
    hostname = hostname_from_url("https://aleph.im")
    assert hostname == "aleph.im"
    hostname = hostname_from_url("aleph.im")
    assert hostname == "aleph.im"


@pytest.mark.asyncio
async def test_query():
    alephdns = DomainValidator()
    hostname = hostname_from_url("https://aleph.im")
    query = await alephdns.resolver.query(hostname, "A")
    assert query is not None
    assert len(query) > 0
    assert hasattr(query[0], "host")


@pytest.mark.asyncio
async def test_get_ipv6_address():
    alephdns = DomainValidator()
    url = "https://aleph.im"
    hostname = hostname_from_url(url)
    ipv6_addresses = await alephdns.get_ipv6_addresses(hostname)
    assert ipv6_addresses is not None
    assert len(ipv6_addresses) > 0
    assert ":" in str(ipv6_addresses[0])


@pytest.mark.asyncio
async def test_dnslink():
    alephdns = DomainValidator()
    url = "https://aleph.im"
    hostname = hostname_from_url(url)
    dnslink = await alephdns.get_dnslink(hostname)
    assert dnslink is not None


@pytest.mark.asyncio
async def test_configured_domain():
    alephdns = DomainValidator()
    url = "https://custom-domain-unit-test.aleph.sh"
    hostname = hostname_from_url(url)
    status = await alephdns.check_domain(hostname, TargetType.IPFS, "0xfakeaddress")
    assert isinstance(status, dict)


@pytest.mark.asyncio
async def test_not_configured_domain():
    alephdns = DomainValidator()
    url = "https://not-configured-domain.aleph.sh"
    hostname = hostname_from_url(url)
    with pytest.raises(DomainConfigurationError):
        status = await alephdns.check_domain(hostname, TargetType.IPFS, "0xfakeaddress")
        assert status is None
