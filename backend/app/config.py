import json
import logging
import os
from typing import Annotated, Any, List, Tuple, Type, Union
from pydantic import field_validator
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    NoDecode,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

def clean_origin(origin: str) -> str:
    """Normalize origin string by stripping whitespace, quotes, and trailing slashes."""
    origin = origin.strip().strip("'\"").strip()
    if origin.endswith("/") and not origin.endswith("://"):
        origin = origin.rstrip("/")
    return origin

class ThreatLensEnvSource(EnvSettingsSource):
    """
    Custom EnvSettingsSource that safely decodes CORS_ORIGINS.
    Prevents pydantic-settings from throwing SettingsError when CORS_ORIGINS is provided
    as a comma-separated string, single origin, or JSON array.
    """
    def decode_complex_value(self, field_name: str, field: FieldInfo, value: Any) -> Any:
        if field_name == "CORS_ORIGINS" and isinstance(value, str):
            val = value.strip()
            if (val.startswith("[") and val.endswith("]")) or (val.startswith("{") and val.endswith("}")):
                try:
                    return json.loads(val)
                except Exception:
                    pass
            return val
        try:
            return super().decode_complex_value(field_name, field, value)
        except Exception:
            return value

class ThreatLensDotEnvSource(DotEnvSettingsSource):
    """
    Custom DotEnvSettingsSource that safely decodes CORS_ORIGINS from .env files.
    """
    def decode_complex_value(self, field_name: str, field: FieldInfo, value: Any) -> Any:
        if field_name == "CORS_ORIGINS" and isinstance(value, str):
            val = value.strip()
            if (val.startswith("[") and val.endswith("]")) or (val.startswith("{") and val.endswith("}")):
                try:
                    return json.loads(val)
                except Exception:
                    pass
            return val
        try:
            return super().decode_complex_value(field_name, field, value)
        except Exception:
            return value

class Settings(BaseSettings):
    APP_NAME: str = "ThreatLens AI"
    APP_ENV: str = "development"
    DATABASE_URL: str = "sqlite:///./threatlens.db"

    # Threat Intelligence API Keys (optional; app functions in setup mode if omitted)
    VIRUSTOTAL_API_KEY: str = ""
    OTX_API_KEY: str = ""

    # External API Request Timeout in seconds
    REQUEST_TIMEOUT_SECONDS: float = 12.0

    # Reliability, Retries & Caching
    MAX_RETRIES: int = 2
    RETRY_BASE_BACKOFF: float = 1.0
    CACHE_TTL_SECONDS: int = 600

    # Authentication & Security
    JWT_SECRET_KEY: str = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    COOKIE_SECURE: bool = False
    COOKIE_SAMESITE: str = "lax"

    # Bootstrap First Administrator
    ADMIN_INITIAL_USERNAME: str = "admin"
    ADMIN_INITIAL_EMAIL: str = "admin@threatlens.ai"
    ADMIN_INITIAL_PASSWORD: str = "Admin@ThreatLens2026!"

    # CORS Origins allowed for frontend
    CORS_ORIGINS: Annotated[Union[List[str], str], NoDecode] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://localhost:3000",
        "http://localhost:5176",
        "http://127.0.0.1:5176",
        "https://threatlens-cyber-threat-intelligence.vercel.app",
        "https://threatlens.vercel.app",
    ]

    model_config = SettingsConfigDict(
        env_file=(".env", "backend/.env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            ThreatLensEnvSource(
                settings_cls,
                case_sensitive=env_settings.case_sensitive,
                env_prefix=env_settings.env_prefix,
                env_nested_delimiter=env_settings.env_nested_delimiter,
            ),
            ThreatLensDotEnvSource(
                settings_cls,
                env_file=dotenv_settings.env_file,
                env_file_encoding=dotenv_settings.env_file_encoding,
                case_sensitive=dotenv_settings.case_sensitive,
                env_prefix=dotenv_settings.env_prefix,
                env_nested_delimiter=dotenv_settings.env_nested_delimiter,
            ),
            file_secret_settings,
        )

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v) -> List[str]:
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return []
            if (v.startswith("[") and v.endswith("]")) or (v.startswith("{") and v.endswith("}")):
                try:
                    parsed = json.loads(v)
                    if isinstance(parsed, list):
                        return [clean_origin(str(o)) for o in parsed if o and clean_origin(str(o))]
                except Exception:
                    pass
            origins = [clean_origin(o) for o in v.split(",") if clean_origin(o)]
        elif isinstance(v, (list, tuple, set)):
            origins = [clean_origin(str(o)) for o in v if o and clean_origin(str(o))]
        else:
            origins = []

        # Enforce CORS security: Never permit wildcard origins when credentials/cookies are enabled
        if "*" in origins:
            logging.getLogger("uvicorn.error").warning(
                "[SECURITY WARNING] Wildcard '*' CORS origin is not permitted with credentialed authentication. Removing '*'."
            )
            origins = [o for o in origins if o != "*"]

        return origins

    @field_validator("COOKIE_SECURE", mode="before")
    @classmethod
    def validate_cookie_secure(cls, v):
        if isinstance(v, str):
            return v.lower() in ("true", "1", "yes")
        return bool(v)

    @field_validator("ADMIN_INITIAL_PASSWORD", mode="before")
    @classmethod
    def validate_admin_initial_password(cls, v):
        if isinstance(v, str):
            v = v.strip()
            if not v or len(v) < 8:
                return "Admin@ThreatLens2026!"
        return v or "Admin@ThreatLens2026!"

    @field_validator("ADMIN_INITIAL_USERNAME", mode="before")
    @classmethod
    def validate_admin_initial_username(cls, v):
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return "admin"
        return v or "admin"

    @field_validator("ADMIN_INITIAL_EMAIL", mode="before")
    @classmethod
    def validate_admin_initial_email(cls, v):
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return "admin@threatlens.ai"
        return v or "admin@threatlens.ai"

settings = Settings()
