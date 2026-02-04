import logging
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from tools.docker_runner import get_docker_runner

logger = logging.getLogger(__name__)


class TechnologyInfo(BaseModel):
    """Information about a detected technology"""

    name: str = Field(description="Technology name")
    version: str | None = Field(description="Version if detected")
    details: dict = Field(default_factory=dict, description="Additional details")


class FingerprintResult(BaseModel):
    """Technology fingerprint for a URL"""

    url: str = Field(description="Target URL")
    technologies: list[TechnologyInfo] = Field(description="Detected technologies")
    error: str | None = Field(description="Error message if scan failed")


class BatchFingerprintResult(BaseModel):
    """Results from fingerprinting multiple URLs"""

    total_scanned: int = Field(description="Number of URLs scanned")
    successful: int = Field(description="Number of successful scans")
    results: list[FingerprintResult] = Field(description="Individual results")


@tool
def fingerprint_technology(url: str) -> FingerprintResult:
    """
    Perform technology fingerprinting on a URL using WhatWeb.

    WhatWeb identifies websites and recognizes web technologies including
    CMS platforms, JavaScript libraries, web servers, embedded devices,
    version numbers, email addresses, and more.

    This runs inside a Docker container for isolation.

    Args:
        url: The URL to fingerprint (e.g., "https://example.com")

    Returns:
        FingerprintResult with detected technologies
    """
    # Ensure URL has scheme
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    logger.info(f"Fingerprinting: {url}")

    runner = get_docker_runner()

    try:
        result = runner.run_whatweb(url, timeout=60)

        technologies = []
        for tech in result.get("technologies", []):
            technologies.append(
                TechnologyInfo(
                    name=tech.get("name", "unknown"),
                    version=tech.get("version"),
                    details=tech.get("details", {}),
                )
            )

        return FingerprintResult(
            url=url,
            technologies=technologies,
            error=result.get("error"),
        )

    except Exception as e:
        logger.error(f"Fingerprinting failed for {url}: {e}")
        return FingerprintResult(
            url=url,
            technologies=[],
            error=str(e),
        )


@tool
def fingerprint_multiple_urls(urls: list[str]) -> BatchFingerprintResult:
    """
    Fingerprint multiple URLs for technology detection.

    Efficiently scans multiple targets and aggregates results.
    Limited to 10 URLs per call to avoid timeout issues.

    Args:
        urls: List of URLs to fingerprint (max 10)

    Returns:
        BatchFingerprintResult with all scan results
    """
    # Limit to prevent abuse
    urls = urls[:10]

    logger.info(f"Batch fingerprinting {len(urls)} URLs")

    results = []
    successful = 0

    for url in urls:
        result = fingerprint_technology.invoke(url)
        results.append(result)
        if not result.error:
            successful += 1

    return BatchFingerprintResult(
        total_scanned=len(urls),
        successful=successful,
        results=results,
    )
