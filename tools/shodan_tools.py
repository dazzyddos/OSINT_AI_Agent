import logging
import os

import shodan
from langchain_core.tools import tool
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ShodanHostResult(BaseModel):
    """Shodan information for a single host"""

    ip: str = Field(description="IP address")
    hostnames: list[str] = Field(description="Associated hostnames")
    ports: list[int] = Field(description="Open ports")
    vulns: list[str] = Field(description="Known CVEs")
    os: str | None = Field(description="Detected operating system")
    services: list[dict] = Field(description="Detailed service information")


class ShodanSearchResult(BaseModel):
    """Results from Shodan domain search"""

    domain: str = Field(description="Searched domain")
    total_results: int = Field(description="Total number of results")
    hosts: list[dict] = Field(description="List of discovered hosts")


@tool
def shodan_host_lookup(ip: str) -> ShodanHostResult:
    """
    Query Shodan for detailed information about a specific IP address.

    Returns open ports, running services, detected vulnerabilities (CVEs),
    and operating system information.

    Args:
        ip: The IP address to look up (e.g., "93.184.216.34")

    Returns:
        ShodanHostResult with comprehensive host information
    """
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return ShodanHostResult(
            ip=ip,
            hostnames=[],
            ports=[],
            vulns=[],
            os=None,
            services=[{"error": "SHODAN_API_KEY not set"}],
        )

    api = shodan.Shodan(api_key)

    try:
        result = api.host(ip)

        services = []
        for item in result.get("data", []):
            service = {
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product", "unknown"),
                "version": item.get("version", ""),
                "cpe": item.get("cpe", []),
            }

            # Include truncated banner for context
            banner = item.get("data", "")
            if banner:
                service["banner_preview"] = banner[:300]

            services.append(service)

        return ShodanHostResult(
            ip=ip,
            hostnames=result.get("hostnames", []),
            ports=result.get("ports", []),
            vulns=list(result.get("vulns", {}).keys()),
            os=result.get("os"),
            services=services,
        )

    except shodan.APIError as e:
        logger.error(f"Shodan API error for {ip}: {e}")
        return ShodanHostResult(
            ip=ip,
            hostnames=[],
            ports=[],
            vulns=[],
            os=None,
            services=[{"error": str(e)}],
        )


@tool
def shodan_domain_search(domain: str) -> ShodanSearchResult:
    """
    Search Shodan for all hosts associated with a domain.

    This finds servers, IPs, and services linked to the target domain
    that are indexed in Shodan's database.

    Args:
        domain: The domain to search for (e.g., "example.com")

    Returns:
        ShodanSearchResult with all discovered hosts
    """
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return ShodanSearchResult(
            domain=domain,
            total_results=0,
            hosts=[{"error": "SHODAN_API_KEY not set"}],
        )

    api = shodan.Shodan(api_key)

    try:
        # Search for hosts with this domain in their hostname
        results = api.search(f"hostname:{domain}")

        hosts = []
        for match in results.get("matches", [])[:25]:  # Limit results
            hosts.append(
                {
                    "ip": match.get("ip_str"),
                    "port": match.get("port"),
                    "hostnames": match.get("hostnames", []),
                    "product": match.get("product", "unknown"),
                    "version": match.get("version", ""),
                    "org": match.get("org", "unknown"),
                    "asn": match.get("asn", ""),
                    "isp": match.get("isp", ""),
                }
            )

        return ShodanSearchResult(
            domain=domain,
            total_results=results.get("total", 0),
            hosts=hosts,
        )

    except shodan.APIError as e:
        logger.error(f"Shodan search error for {domain}: {e}")
        return ShodanSearchResult(
            domain=domain,
            total_results=0,
            hosts=[{"error": str(e)}],
        )
