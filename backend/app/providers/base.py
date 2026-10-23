from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import re
import httpx
from pydantic import BaseModel, Field

class ProviderResult(BaseModel):
    provider_name: str
    status: str # "success", "clean", "not_found", "missing_key", "rate_limited", "unauthorized", "error", "unsupported"
    is_malicious: bool = False
    detections: int = 0
    total_engines: int = 0
    reputation_score: Optional[float] = None
    summary: str = ""
    error_message: Optional[str] = None
    queried_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    attributes: Dict[str, Any] = Field(default_factory=dict)
    cached: bool = False
    response_time_ms: Optional[float] = None

class BaseThreatProvider(ABC):
    def __init__(
        self,
        api_key: str,
        timeout: float = 12.0,
        max_retries: int = 2,
        base_backoff_seconds: float = 1.0,
        max_backoff_seconds: float = 10.0
    ):
        self.api_key = api_key.strip() if api_key else ""
        self.timeout = timeout
        self.max_retries = max_retries
        self.base_backoff_seconds = base_backoff_seconds
        self.max_backoff_seconds = max_backoff_seconds

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def _parse_retry_after(self, response: httpx.Response, default: float = 2.0) -> float:
        """Parses Retry-After header as integer/float seconds, bounded by max_backoff_seconds."""
        retry_val = response.headers.get("retry-after")
        if not retry_val:
            return default
        try:
            val = float(retry_val.strip())
            return min(max(0.5, val), self.max_backoff_seconds)
        except ValueError:
            # If HTTP date format, fallback to default
            return default

    def _sanitize_error_text(self, text: str) -> str:
        """Sanitizes text to prevent API keys or internal tokens from leaking into user error messages."""
        if not text:
            return ""
        if self.api_key and len(self.api_key) >= 6:
            text = text.replace(self.api_key, "[REDACTED_API_KEY]")
        # Redact generic long hex/alphanumeric tokens
        text = re.sub(r'([a-fA-F0-9]{32,64})', '[REDACTED_API_KEY]', text)
        return text[:250]

    @abstractmethod
    async def lookup(self, indicator: str, indicator_type: str) -> ProviderResult:
        pass
