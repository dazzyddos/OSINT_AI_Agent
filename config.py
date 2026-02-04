import os
from dataclasses import dataclass


@dataclass
class Config:
    """Application configuration"""

    # API Keys
    deepseek_api_key: str = os.getenv("DEEPSEEK_API_KEY", "")
    shodan_api_key: str = os.getenv("SHODAN_API_KEY", "")

    # DeepSeek settings
    deepseek_base_url: str = "https://api.deepseek.com"

    # Docker settings
    docker_image: str = os.getenv("OSINT_DOCKER_IMAGE", "osint-tools:latest")
    docker_timeout: int = int(os.getenv("DOCKER_TIMEOUT", "300"))

    # Agent settings
    llm_model: str = os.getenv("LLM_MODEL", "deepseek-chat")
    llm_temperature: float = float(os.getenv("LLM_TEMPERATURE", "0"))

    # Limits
    max_subdomains_to_fingerprint: int = 10
    max_shodan_results: int = 25

    def validate(self) -> bool:
        """Validate required configuration"""
        if not self.deepseek_api_key:
            raise ValueError("DEEPSEEK_API_KEY is required")
        return True


config = Config()
