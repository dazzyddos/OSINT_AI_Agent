import docker
import json
import logging
import shlex
from typing import Optional

logger = logging.getLogger(__name__)


class DockerToolRunner:
    """Execute reconnaissance tools inside Docker containers"""

    def __init__(self, image: str = "osint-tools:latest"):
        self.client = docker.from_env()
        self.image = image
        self._ensure_image_exists()

    def _ensure_image_exists(self) -> None:
        """Check if the tools image exists, raise error if not"""
        try:
            self.client.images.get(self.image)
        except docker.errors.ImageNotFound:
            raise RuntimeError(
                f"Docker image '{self.image}' not found. "
                f"Build it with: docker build -t {self.image} -f docker/Dockerfile.tools ."
            )

    def run_command(
        self,
        command: str,
        timeout: int = 300,
        network_mode: str = "bridge",
        env_vars: Optional[dict] = None,
    ) -> tuple[str, str, int]:
        """
        Run a command inside the Docker container.

        Args:
            command: The command to execute
            timeout: Maximum execution time in seconds
            network_mode: Docker network mode (bridge, host, none)
            env_vars: Environment variables to pass to container

        Returns:
            Tuple of (stdout, stderr, exit_code)
        """
        container = None
        try:
            container = self.client.containers.run(
                self.image,
                command=f"/bin/bash -c {shlex.quote(command)}",
                detach=True,
                remove=False,
                network_mode=network_mode,
                environment=env_vars or {},
                mem_limit="512m",
                cpu_period=100000,
                cpu_quota=50000,  # Limit to 50% CPU
            )

            # Wait for completion with timeout
            result = container.wait(timeout=timeout)
            exit_code = result["StatusCode"]

            # Get logs
            stdout = container.logs(stdout=True, stderr=False).decode("utf-8")
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8")

            return stdout, stderr, exit_code

        except docker.errors.ContainerError as e:
            logger.error(f"Container error: {e}")
            return "", str(e), 1
        except Exception as e:
            logger.error(f"Docker execution failed: {e}")
            raise
        finally:
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass

    def run_subfinder(self, domain: str, timeout: int = 120) -> list[str]:
        """Run Subfinder for subdomain enumeration"""
        # Sanitize domain input
        safe_domain = shlex.quote(domain)
        command = f"subfinder -d {safe_domain} -silent -json"
        stdout, stderr, exit_code = self.run_command(command, timeout=timeout)

        subdomains = []
        for line in stdout.strip().split("\n"):
            if line:
                try:
                    data = json.loads(line)
                    host = data.get("host", "")
                    if host:
                        subdomains.append(host)
                except json.JSONDecodeError:
                    # Plain text output fallback
                    cleaned = line.strip()
                    if cleaned and "." in cleaned:
                        subdomains.append(cleaned)

        return [s for s in subdomains if s]

    def run_whatweb(self, url: str, timeout: int = 60) -> dict:
        """Run WhatWeb for technology fingerprinting"""
        # Escape URL for shell
        safe_url = shlex.quote(url)
        command = f"whatweb {safe_url} --log-json=/dev/stdout --quiet"

        stdout, stderr, exit_code = self.run_command(command, timeout=timeout)

        result = {
            "url": url,
            "technologies": [],
            "raw_output": stdout,
            "error": stderr if exit_code != 0 else None,
        }

        # Parse WhatWeb JSON output
        for line in stdout.strip().split("\n"):
            if line:
                try:
                    data = json.loads(line)
                    # WhatWeb returns array of results
                    if isinstance(data, list):
                        for item in data:
                            result["technologies"].extend(
                                self._parse_whatweb_plugins(item)
                            )
                    elif isinstance(data, dict):
                        result["technologies"].extend(self._parse_whatweb_plugins(data))
                except json.JSONDecodeError:
                    continue

        return result

    def _parse_whatweb_plugins(self, data: dict) -> list[dict]:
        """Parse WhatWeb plugin output into structured format"""
        technologies = []
        plugins = data.get("plugins", {})

        for plugin_name, plugin_data in plugins.items():
            tech = {"name": plugin_name, "version": None, "details": {}}

            # Extract version if available
            if isinstance(plugin_data, dict):
                if "version" in plugin_data:
                    versions = plugin_data["version"]
                    if versions:
                        tech["version"] = (
                            versions[0] if isinstance(versions, list) else versions
                        )

                # Extract other interesting fields
                for key in ["string", "account", "module"]:
                    if key in plugin_data and plugin_data[key]:
                        tech["details"][key] = plugin_data[key]

            technologies.append(tech)

        return technologies

    def run_httpx(self, targets: list[str], timeout: int = 120) -> list[dict]:
        """Run httpx to probe live hosts"""
        # Write targets via stdin
        targets_str = "\\n".join(targets)
        command = f"echo -e '{targets_str}' | httpx -silent -json -status-code -title -tech-detect"

        stdout, stderr, exit_code = self.run_command(command, timeout=timeout)

        results = []
        for line in stdout.strip().split("\n"):
            if line:
                try:
                    data = json.loads(line)
                    results.append(
                        {
                            "url": data.get("url", ""),
                            "status_code": data.get("status_code"),
                            "title": data.get("title", ""),
                            "technologies": data.get("tech", []),
                            "content_length": data.get("content_length"),
                        }
                    )
                except json.JSONDecodeError:
                    continue

        return results


# Singleton instance for reuse
_runner: Optional[DockerToolRunner] = None


def get_docker_runner() -> DockerToolRunner:
    """Get or create the Docker runner instance"""
    global _runner
    if _runner is None:
        _runner = DockerToolRunner()
    return _runner
