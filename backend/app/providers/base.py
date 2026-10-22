from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime, timezone
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

class BaseThreatProvider(ABC):
    def __init__(self, api_key: str, timeout: float = 12.0):
        self.api_key = api_key.strip() if api_key else ""
        self.timeout = timeout
        
    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)
        
    @abstractmethod
    async def lookup(self, indicator: str, indicator_type: str) -> ProviderResult:
        pass
