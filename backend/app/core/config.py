"""
TrustShield AI — Cyber Resilience Backend
Core configuration using pydantic-settings.

Reads from environment variables / .env file.
All secrets must be set in .env, never hardcoded here.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import List
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_env: str = Field(default="development")
    app_host: str = Field(default="0.0.0.0")
    app_port: int = Field(default=8000)
    app_log_level: str = Field(default="info")

    # CORS — accept comma-separated origins from env
    cors_origins: str = Field(
        default="http://localhost:5173,http://localhost:3000"
    )

    @property
    def cors_origins_list(self) -> List[str]:
        """Parse comma-separated CORS origins into a list."""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    # Threat Intelligence
    urlhaus_api_url: str = Field(
        default="https://urlhaus-api.abuse.ch/v1/"
    )
    phishtank_api_key: str = Field(default="")
    phishtank_api_url: str = Field(
        default="https://checkurl.phishtank.com/checkurl/"
    )
    threat_intel_timeout_seconds: int = Field(default=5)
    threat_intel_enabled: bool = Field(default=True)

    # Rate limiting (reserved for future use)
    rate_limit_per_minute: int = Field(default=60)


# Singleton settings instance — import this everywhere
settings = Settings()
