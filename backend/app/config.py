import os
from typing import List
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "ThreatLens AI"
    APP_ENV: str = "development"
    DATABASE_URL: str = "sqlite:///./threatlens.db"
    
    # Threat Intelligence API Keys (optional; app functions in setup mode if omitted)
    VIRUSTOTAL_API_KEY: str = ""
    OTX_API_KEY: str = ""
    
    # External API Request Timeout in seconds
    REQUEST_TIMEOUT_SECONDS: float = 12.0
    
    # CORS Origins allowed for frontend
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://localhost:3000",
        "http://localhost:5176",
        "http://127.0.0.1:5176",
    ]
    
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

settings = Settings()
