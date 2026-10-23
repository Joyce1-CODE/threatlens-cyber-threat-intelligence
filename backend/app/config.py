import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict

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
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://localhost:3000",
        "http://localhost:5176",
        "http://127.0.0.1:5176",
    ]

    model_config = SettingsConfigDict(
        env_file=(".env", "backend/.env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

settings = Settings()
