import aiodns
import re
from .conf import settings
from typing import Optional
from aleph.sdk.exceptions import DomainConfigurationError


class AlephDNS:
    def __init__(self):
        self.resolver = aiodns.DNSResolver(servers=settings.RESOLVERS)
        self.fqdn_matcher = re.compile(r"https?://?")

    async def query(self, name: str, query_type: str):
        try:
            return await self.resolver.query(name, query_type)
        except Exception as e:
            print(e)
            return None

    def url_to_domain(self, url):
        return self.fqdn_matcher.sub("", url).strip().strip("/")

    async def get_ipv6_address(self, url: str):
        domain = self.url_to_domain(url)
        ipv6 = []
        query = await self.query(domain, "AAAA")
        if query:
            for entry in query:
                ipv6.append(entry.host)
        return ipv6

    async def get_dnslink(self, url: str):
        domain = self.url_to_domain(url)
        query = await self.query(f"_dnslink.{domain}", "TXT")
        if query is not None and len(query) > 0:
            return query[0].text

    async def get_control(self, url: str):
        domain = self.url_to_domain(url)
        query = await self.query(f"_control.{domain}", "TXT")
        if query is not None and len(query) > 0:
            return query[0].text

    async def check_domain_configured(self, domain, _type, owner):
        try:
            print("Check...", _type)
            return await self.check_domain(domain, _type, owner)
        except Exception as error:
            raise DomainConfigurationError(error)

    async def check_domain(self, url: str, _type: str, owner: Optional[str] = None):
        # if _type.lower() == 'ipfs':
        return await self.check_ipfs_domain(url, _type, owner)
        # elif _type.lower() == 'program':
        #    pass

    async def check_ipfs_domain(
        self, url: str, _type: str, owner: Optional[str] = None
    ):
        status = {"cname": True, "owner_proof": False}

        _type = _type.lower()
        domain = self.url_to_domain(url)

        if _type == "ipfs":
            status["delegation"] = False

        # check1: CNAME value should be ipfs or program
        res = await self.query(domain, "CNAME")
        if _type.lower() == "ipfs":
            expected_value = settings.IPFS_DOMAINS
        else:
            expected_value = settings.PROGRAM_DOMAINS

        assert_error = (
            f"CNAME record not found: {domain}",
            f"Create a CNAME record for {domain} with values {expected_value}",
            status,
        )

        assert res is not None, assert_error
        assert hasattr(res, "cname"), assert_error

        assert_error = (
            f"{domain} should have a valid CNAME value, {res.cname} provided",
            f"Create a CNAME record for {domain} with values {expected_value}",
            status,
        )
        assert res.cname in expected_value, assert_error
        status["cname"] = True

        if _type.lower() == "ipfs":
            # check2: CNAME value of _dnslink.__custom_domain__
            # should be _dnslink.__custom_domain__.static.public.aleph.sh
            res = await self.query(f"_dnslink.{domain}", "CNAME")

            expected_value = f"_dnslink.{domain}.{settings.ROOT_DOMAIN}"
            assert_error = (
                f"CNAME record not found: _dnslink.{domain}",
                f"Create a CNAME record for _dnslink.{domain} with value: {expected_value}",
                status,
            )

            assert res is not None, assert_error
            assert hasattr(res, "cname"), assert_error
            assert res.cname == expected_value, assert_error
            status["delegation"] = True

        # check3: TXT value of _control.__custom_domain__ should be the address of the owner
        owner_address = await self.get_control(domain)
        assert_error = (
            f"TXT record not found: _control.{domain}",
            f'Create a TXT record for _control.{domain} with value = "owner address"',
            status,
        )
        assert owner_address is not None, assert_error

        if owner is not None:
            assert owner_address == owner, (
                f"Owner address mismatch, got: {owner} expected: {owner_address}",
                f"",
                status,
            )
            status["owner_proof"] = True

        return status
