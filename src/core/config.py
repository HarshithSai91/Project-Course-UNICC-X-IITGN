"""
Application configuration using pydantic-settings.

All settings are overridable via environment variables.
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Environment-driven configuration for the Threat Matching Subsystem."""

    # Retrieval backend: "mock" (default) or "live" (swap when teammates ready)
    RETRIEVAL_BACKEND: str = "mock"

    # Logging
    LOG_LEVEL: str = "INFO"

    # API
    API_PREFIX: str = "/api/v1"
    APP_VERSION: str = "0.1.0"

    # CORS
    CORS_ORIGINS: list[str] = ["*"]

    model_config = {"env_prefix": "", "case_sensitive": True}


def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
