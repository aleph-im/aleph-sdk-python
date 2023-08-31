import re
from typing import Optional

import aiodns

from aleph.sdk.exceptions import DomainConfigurationError

from .conf import settings


class AlephDNS:
    def __init__(self):
        self.resolver = aiodns.DNSResolver(servers=settings.DNS_RESOLVERS)
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

    async def check_domain_configured(self, domain, target, owner):
        try:
            print("Check...", target)
            return await self.check_domain(domain, target, owner)
        except Exception as error:
            raise DomainConfigurationError(error)

    async def check_domain(self, url: str, target: str, owner: Optional[str] = None):
        status = {"cname": False, "owner_proof": False}

        target = target.lower()
        domain = self.url_to_domain(url)

        dns_rules = self.get_required_dns_rules(url, target, owner)

        for dns_rule in dns_rules:
            status[dns_rule["rule_name"]] = False

            record_name = dns_rule["dns"]["name"]
            record_type = dns_rule["dns"]["type"]
            record_value = dns_rule["dns"]["value"]

            res = await self.query(record_name, record_type.upper())

            if record_type == "txt":
                found = False

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

    def get_required_dns_rules(self, url, target, owner: Optional[str] = None):
        domain = self.url_to_domain(url)
        target = target.lower()
        dns_rules = []

        if target == "ipfs":
            cname_value = settings.DNS_IPFS_DOMAIN
        elif target == "program":
            cname_value = settings.DNS_PROGRAM_DOMAIN
        elif target == "instance":
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

        if target == "ipfs":
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
