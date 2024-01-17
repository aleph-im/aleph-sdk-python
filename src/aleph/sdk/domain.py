import logging
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Any, AsyncIterable, Dict, Iterable, List, NewType, Optional, Union
from urllib.parse import urlparse

import aiodns
from pydantic import BaseModel, HttpUrl

from .conf import settings
from .exceptions import DomainConfigurationError

logger = logging.getLogger(__name__)

Hostname = NewType("Hostname", str)


class TargetType(str, Enum):
    """
    The type of target that a domain points to.

    - IPFS: The domain points to an IPFS hash.
    - PROGRAM: The domain points to an aleph.im program.
    - INSTANCE: The domain points to an aleph.im instance.
    """

    IPFS = "ipfs"
    PROGRAM = "program"
    INSTANCE = "instance"


class DNSRule(BaseModel):
    """
    A DNS rule is a DNS record that is required for a domain to be configured.

    Args:
        name: The name of the rule.
        dns: The DNS record.
        info: Instructions to configure the DNS record.
        on_error: Error message when the rule is not found.
    """

    name: str
    dns: Dict[str, Any]
    info: str
    on_error: str

    def raise_error(self, status: Dict[str, bool]):
        raise DomainConfigurationError((self.info, self.on_error, status))


def hostname_from_url(url: Union[HttpUrl, str]) -> Hostname:
    """Extract FQDN from url"""

    parsed = urlparse(url)
    if all([parsed.scheme, parsed.netloc]) is True:
        url = parsed.netloc

    return Hostname(url)


async def get_target_type(fqdn: Hostname) -> Optional[TargetType]:
    """Returns the aleph.im target type of the domain"""
    domain_validator = DomainValidator()
    resolver = await domain_validator.get_resolver_for(fqdn)
    try:
        entry = await resolver.query(fqdn, "CNAME")
        cname = getattr(entry, "cname")
        if settings.DNS_IPFS_DOMAIN in cname:
            return TargetType.IPFS
        elif settings.DNS_PROGRAM_DOMAIN in cname:
            return TargetType.PROGRAM
        elif settings.DNS_INSTANCE_DOMAIN in cname:
            return TargetType.INSTANCE

        return None
    except aiodns.error.DNSError:
        return None


class DomainValidator:
    """
    Tools used to analyze domain names used on the aleph.im network.
    """

    resolver: aiodns.DNSResolver

    def __init__(self):
        self.resolver = aiodns.DNSResolver(servers=settings.DNS_RESOLVERS)

    async def get_name_servers(self, hostname: Hostname):
        """Get DNS name servers (NS) of a domain"""
        dns_servers = settings.DNS_RESOLVERS
        fqdn = hostname

        while True:
            # Detect and get authoritative NS of subdomains if delegated
            try:
                entries = await self.resolver.query(fqdn, "NS")
                servers: List[Any] = []
                for entry in entries:
                    servers += await self.get_ipv6_addresses(entry.host)
                    servers += await self.get_ipv4_addresses(entry.host)

                dns_servers = servers
                break
            except aiodns.error.DNSError:
                sub_domains = fqdn.split(".")
                if len(sub_domains) > 2:
                    fqdn = Hostname(".".join(sub_domains[1:]))
                    continue

                if len(sub_domains) == 2:
                    break
            except Exception as err:
                logger.debug(f"Unexpected {err=}, {type(err)=}")
                break

        return dns_servers

    async def get_resolver_for(self, hostname: Hostname):
        dns_servers = await self.get_name_servers(hostname)
        return aiodns.DNSResolver(servers=dns_servers)

    async def get_ipv4_addresses(self, hostname: Hostname) -> List[IPv4Address]:
        """Returns all IPv4 addresses for a domain"""
        entries: Iterable = await self.resolver.query(hostname, "A") or []
        return [entry.host for entry in entries]

    async def get_ipv6_addresses(self, hostname: Hostname) -> List[IPv6Address]:
        """Returns all IPv6 addresses for a domain"""
        entries: Iterable = await self.resolver.query(hostname, "AAAA") or []
        return [entry.host for entry in entries]

    async def get_dnslinks(self, hostname: Hostname) -> List[str]:
        """Returns all DNSLink values for a domain."""
        entries = await self.resolver.query(f"_dnslink.{hostname}", "TXT")
        return [entry.text for entry in entries]

    async def get_dnslink(self, hostname: Hostname) -> Optional[str]:
        """Returns the DNSLink corresponding to a domain.

        Since it is possible to add multiple TXT records containing a DNSLink to
        the same domain, a behaviour has to be defined.

        - Some IPFS implementations might use the first valid dnslink= record they find.
        - Others might throw an error indicating that the DNSLink resolution is ambiguous due to multiple records.
        - Still, others might try to fetch content from all provided DNSLinks,
          though this behavior would be less common and may introduce overhead.
        """
        dnslinks = await self.get_dnslinks(hostname)
        return dnslinks[0] if dnslinks else None

    async def get_txt_values(
        self, hostname: Hostname, delimiter: Optional[str] = None
    ) -> AsyncIterable[str]:
        """Returns all TXT values for a domain"""
        entries: Iterable = await self.resolver.query(hostname, "TXT") or []
        for entry in entries:
            if not hasattr(entry, "text"):
                logger.debug("An entry does not have any text")
                continue
            if not entry.text.startswith("0x"):
                logger.debug("Does not look like an Ethereum address")
                continue

            if delimiter:
                for part in entry.text.split(delimiter):
                    yield part
            else:
                yield entry.text

    async def check_domain(
        self, hostname: Hostname, target: TargetType, owner: Optional[str] = None
    ) -> Dict:
        """
        Checks that the domain points towards the given aleph.im target.

        Args:
            hostname: The hostname of the domain.
            target: The aleph.im target type.
            owner: The owner wallet address of the domain for ownership proof.

        Raises:
            DomainConfigurationError: If the domain is not configured.

        Returns:
            A dictionary containing the status of the domain configuration.
        """
        status = {}

        dns_rules = self.get_required_dns_rules(hostname, target, owner)
        resolver = await self.get_resolver_for(hostname)
        for dns_rule in dns_rules:
            status[dns_rule.name] = False

            record_name = dns_rule.dns["name"]
            record_type = dns_rule.dns["type"]
            record_value = dns_rule.dns["value"]

            try:
                entries = await resolver.query(record_name, record_type.upper())
            except aiodns.error.DNSError:
                # Continue checks
                entries = None

            if entries:
                if record_type == "txt":
                    for entry in entries:
                        if hasattr(entry, "text") and entry.text == record_value:
                            status[dns_rule.name] = True
                            break
                elif (
                    hasattr(entries, record_type)
                    and getattr(entries, record_type) == record_value
                ):
                    status[dns_rule.name] = True

        if all(status.values()) is False:
            dns_rule.raise_error(status)

        return status

    def get_required_dns_rules(
        self, hostname: Hostname, target: TargetType, owner: Optional[str] = None
    ) -> List[DNSRule]:
        """
        Returns the DNS rules (CNAME, TXT) required for a domain to be configured.

        Args:
            hostname: The hostname of the domain.
            target: The aleph.im target type.
            owner: The owner wallet address of the domain to add as an ownership proof.

        Returns:
            A list of DNS rules with
        """
        target = target.lower()
        dns_rules = []

        cname_value = None
        if target == TargetType.IPFS:
            cname_value = settings.DNS_IPFS_DOMAIN
        elif target == TargetType.PROGRAM:
            cname_value = f"{hostname}.{settings.DNS_PROGRAM_DOMAIN}"
        elif target == TargetType.INSTANCE:
            cname_value = f"{hostname}.{settings.DNS_INSTANCE_DOMAIN}"

        # cname rule
        dns_rules.append(
            DNSRule(
                name="cname",
                dns={
                    "type": "cname",
                    "name": hostname,
                    "value": cname_value,
                },
                info=f"Create a CNAME record for {hostname} with value {cname_value}",
                on_error=f"CNAME record not found: {hostname}",
            )
        )

        if target == TargetType.IPFS:
            # ipfs rule
            dns_rules.append(
                DNSRule(
                    name="delegation",
                    dns={
                        "type": "cname",
                        "name": f"_dnslink.{hostname}",
                        "value": f"_dnslink.{hostname}.{settings.DNS_STATIC_DOMAIN}",
                    },
                    info=f"Create a CNAME record for _dnslink.{hostname} with value _dnslink.{hostname}.{settings.DNS_STATIC_DOMAIN}",
                    on_error=f"CNAME record not found: _dnslink.{hostname}",
                )
            )

        if owner:
            # ownership rule
            dns_rules.append(
                DNSRule(
                    name="owner_proof",
                    dns={
                        "type": "txt",
                        "name": f"_control.{hostname}",
                        "value": owner,
                    },
                    info=f"Create a TXT record for _control.{hostname} with value {owner}",
                    on_error="Owner address mismatch",
                )
            )

        return dns_rules
