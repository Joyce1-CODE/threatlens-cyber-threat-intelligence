import time
import asyncio
from typing import Dict, Optional

class ProviderRateLimiter:
    """
    Asynchronous token-bucket & pacing rate limiter with circuit-breaker for bulk triage.
    Prevents overwhelming external APIs (e.g. VirusTotal 4 req/min free-tier quota)
    and gracefully handles provider rate-limit exhaustion without failing the whole batch.
    """
    def __init__(
        self,
        vt_interval_seconds: float = 15.0, # 4 req/min = 1 req every 15s
        otx_interval_seconds: float = 0.5, # Generous community tier
    ):
        self.vt_interval = vt_interval_seconds
        self.otx_interval = otx_interval_seconds
        self._last_vt_time = 0.0
        self._last_otx_time = 0.0
        self._vt_lock = asyncio.Lock()
        self._otx_lock = asyncio.Lock()

        # Batch circuit-breaker state (tracks if provider hit 429 quota during batch)
        self.vt_rate_limited = False
        self.otx_rate_limited = False
        self.vt_quota_reset_time: Optional[float] = None
        self.otx_quota_reset_time: Optional[float] = None

    async def acquire_vt(self) -> bool:
        """
        Paces VirusTotal requests according to the free tier quota.
        Returns False if the provider is currently in a 429 cooldown state.
        """
        now = time.time()
        if self.vt_rate_limited:
            if self.vt_quota_reset_time and now >= self.vt_quota_reset_time:
                self.vt_rate_limited = False
                self.vt_quota_reset_time = None
            else:
                return False

        async with self._vt_lock:
            if self.vt_interval > 0:
                elapsed = time.time() - self._last_vt_time
                if elapsed < self.vt_interval:
                    sleep_time = self.vt_interval - elapsed
                    await asyncio.sleep(sleep_time)
            self._last_vt_time = time.time()
            return True

    async def acquire_otx(self) -> bool:
        """
        Paces AlienVault OTX requests.
        Returns False if the provider is currently in a 429 cooldown state.
        """
        now = time.time()
        if self.otx_rate_limited:
            if self.otx_quota_reset_time and now >= self.otx_quota_reset_time:
                self.otx_rate_limited = False
                self.otx_quota_reset_time = None
            else:
                return False

        async with self._otx_lock:
            if self.otx_interval > 0:
                elapsed = time.time() - self._last_otx_time
                if elapsed < self.otx_interval:
                    sleep_time = self.otx_interval - elapsed
                    await asyncio.sleep(sleep_time)
            self._last_otx_time = time.time()
            return True

    def mark_vt_rate_limited(self, cooldown_seconds: float = 60.0) -> None:
        """Engages circuit breaker for VirusTotal when 429 is encountered."""
        self.vt_rate_limited = True
        self.vt_quota_reset_time = time.time() + cooldown_seconds

    def mark_otx_rate_limited(self, cooldown_seconds: float = 60.0) -> None:
        """Engages circuit breaker for AlienVault OTX when 429 is encountered."""
        self.otx_rate_limited = True
        self.otx_quota_reset_time = time.time() + cooldown_seconds

    def reset(self) -> None:
        """Resets all rate limits and cooldown flags."""
        self.vt_rate_limited = False
        self.otx_rate_limited = False
        self.vt_quota_reset_time = None
        self.otx_quota_reset_time = None
        self._last_vt_time = 0.0
        self._last_otx_time = 0.0
