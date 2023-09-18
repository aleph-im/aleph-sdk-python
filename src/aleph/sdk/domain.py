from enum import Enum
from ipaddress import IPv6Address
from typing import List, Optional, Dict, Iterable
from urllib.parse import urlparse

import aiodns
from pydantic import HttpUrl

from aleph.sdk.exceptions import DomainConfigurationError

from .conf import settings


class Target(str, Enum):
    IPFS = "ipfs"
    PROGRAM = "program"
    INSTANCE = "instance"


def domain_from_url(url: HttpUrl) -> str:
    return domain_from_url(url)

class AlephDNS:
    def __init__(self):
        self.resolver = aiodns.DNSResolver(servers=settings.DNS_RESOLVERS)

    async def query(self, name: str, query_type: str):
        return await self.resolver.query(name, query_type)

    async def get_ipv6_address(self, url: HttpUrl) -> Iterable[IPv6Address]:
        domain = domain_from_url(url)
        query = await self.query(domain, "AAAA")
        if query:
            for entry in query:
                yield entry.host

    async def get_dnslink(self, url: HttpUrl) -> Optional[str]:
        domain = domain_from_url(url)
        query = await self.query(f"_dnslink.{domain}", "TXT")
        if query is not None and len(query) > 0:
            return query[0].text
        else:
            return None

    async def get_txt_values(self, url: HttpUrl, delimiter: Optional[str] = None) -> List[str]:
        domain = domain_from_url(url)
        res = await self.query(domain, "TXT")
        values: List[str] = []
        if res is not None:
            for _res in res:
                if hasattr(_res, "text") and _res.text.startswith("0x"):
                    if delimiter is not None and delimiter in _res.text:
                        values = values + _res.text.split(delimiter)
                    else:
                        values.append(_res.text)
        return values

    async def check_domain_configured(self, domain: HttpUrl, target: Target, owner):
        try:
            print("Check...", target)
            return await self.check_domain(domain, target, owner)
        except Exception as error:
            raise DomainConfigurationError(error)

    async def check_domain(self, url: HttpUrl, target: Target, owner: Optional[str] = None):
        """Check that the domain points towards the target.
        """
        status = {"cname": False, "owner_proof": False}

        domain = domain_from_url(url)

        dns_rules = self.get_required_dns_rules(url, target, owner)

        for dns_rule in dns_rules:
            status[dns_rule["rule_name"]] = False

            record_name = dns_rule["dns"]["name"]
            record_type = dns_rule["dns"]["type"]
            record_value = dns_rule["dns"]["value"]

            res = await self.query(record_name, record_type.upper())

            if record_type == "txt":
                found = False
                if res is not None:
                    for _res in res:
                        if hasattr(_res, "text") and _res.text == record_value:
                            found = True
                if found == False:
                    raise DomainConfigurationError(
                        (dns_rule["info"], dns_rule["on_error"], status)
                    )
            elif (
                res is None
                or not hasattr(res, record_type)
                or getattr(res, record_type) != record_value
            ):
                raise DomainConfigurationError(
                    (dns_rule["info"], dns_rule["on_error"], status)
                )

            status[dns_rule["rule_name"]] = True

        return status

    def get_required_dns_rules(self, url: HttpUrl, target: Target, owner: Optional[str] = None) -> List[Dict]:
        domain = domain_from_url(url)
        target = target.lower()
        dns_rules = []

        cname_value = None
        if target == Target.IPFS:
            cname_value = settings.DNS_IPFS_DOMAIN
        elif target == Target.PROGRAM:
            cname_value = f"{domain}.{settings.DNS_PROGRAM_DOMAIN}"
        elif target == Target.INSTANCE:
            cname_value = f"{domain}.{settings.DNS_INSTANCE_DOMAIN}"

        # cname rule
        dns_rules.append(
            {
                "rule_name": "cname",
                "dns": {"type": "cname", "name": domain, "value": cname_value},
                "info": f"Create a CNAME record for {domain} with value {cname_value}",
                "on_error": f"CNAME record not found: {domain}",
            }
        )

        if target == Target.IPFS:
            # ipfs rule
            dns_rules.append(
                {
                    "rule_name": "delegation",
                    "dns": {
                        "type": "cname",
                        "name": f"_dnslink.{domain}",
                        "value": f"_dnslink.{domain}.{settings.DNS_STATIC_DOMAIN}",
                    },
                    "info": f"Create a CNAME record for _dnslink.{domain} with value _dnslink.{domain}.{settings.DNS_STATIC_DOMAIN}",
                    "on_error": f"CNAME record not found: _dnslink.{domain}",
                }
            )

        if owner:
            # ownership rule
            dns_rules.append(
                {
                    "rule_name": "owner_proof",
                    "dns": {
                        "type": "txt",
                        "name": f"_control.{domain}",
                        "value": owner,
                    },
                    "info": f"Create a TXT record for _control.{domain} with value = owner address",
                    "on_error": f"Owner address mismatch",
                }
            )

        return dns_rules
