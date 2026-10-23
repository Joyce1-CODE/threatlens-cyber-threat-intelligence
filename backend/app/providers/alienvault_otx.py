import time
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import httpx

from app.providers.base import BaseThreatProvider, ProviderResult
from app.providers.cache import provider_cache

class AlienVaultOTXProvider(BaseThreatProvider):
    PROVIDER_NAME = "AlienVault OTX"
    BASE_URL = "https://otx.alienvault.com/api/v1"

    async def lookup(self, indicator: str, indicator_type: str, use_cache: bool = True) -> ProviderResult:
        if not self.is_configured:
            return ProviderResult(
                provider_name=self.PROVIDER_NAME,
                status="missing_key",
                summary="AlienVault OTX API key not configured. Add OTX_API_KEY to .env.",
                error_message="Missing API credentials in environment.",
                queried_at=datetime.now(timezone.utc)
            )

        endpoint = self._get_endpoint(indicator, indicator_type)
        if not endpoint:
            return ProviderResult(
                provider_name=self.PROVIDER_NAME,
                status="unsupported",
                summary=f"Indicator type '{indicator_type}' is not supported by AlienVault OTX integration.",
                error_message="Unsupported IOC type",
                queried_at=datetime.now(timezone.utc)
            )

        # Check in-memory cache first
        if use_cache:
            cached_result = provider_cache.get(self.PROVIDER_NAME, indicator_type, indicator)
            if cached_result:
                return cached_result

        headers = {
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json",
            "User-Agent": "ThreatLens-AI/1.0"
        }

        url = f"{self.BASE_URL}{endpoint}"
        start_time = time.time()
        max_attempts = self.max_retries + 1
        last_error_message = None

        for attempt in range(max_attempts):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.get(url, headers=headers)

                elapsed_ms = round((time.time() - start_time) * 1000, 1)

                if response.status_code == 200:
                    data = response.json()
                    pulse_info = data.get("pulse_info", {})
                    pulse_count = pulse_info.get("count", 0)
                    pulses = pulse_info.get("pulses", [])

                    # Extract threat intelligence tags and malware families
                    malware_families = set()
                    adversaries = set()
                    pulse_tags = set()
                    top_pulses = []

                    for p in pulses[:8]: # Inspect top 8 community pulses
                        p_name = p.get("name", "Unnamed Pulse")
                        author = p.get("author_name", "Community")
                        created = p.get("created")

                        for mf in p.get("malware_families", []):
                            if isinstance(mf, dict) and mf.get("display_name"):
                                malware_families.add(mf["display_name"])
                            elif isinstance(mf, str):
                                malware_families.add(mf)

                        adv = p.get("adversary")
                        if adv:
                            adversaries.add(adv)

                        for tag in p.get("tags", []):
                            if isinstance(tag, str):
                                pulse_tags.add(tag)

                        top_pulses.append({
                            "id": p.get("id"),
                            "name": p_name,
                            "author": author,
                            "created": created,
                            "tags": p.get("tags", [])[:5]
                        })

                    is_malicious = (pulse_count > 0)
                    summary = (
                        f"AlienVault OTX reported {pulse_count} community threat pulse(s) associated with this indicator."
                        if pulse_count > 0 else "No threat pulses reported in AlienVault OTX community database."
                    )

                    result = ProviderResult(
                        provider_name=self.PROVIDER_NAME,
                        status="success" if pulse_count > 0 else "clean",
                        is_malicious=is_malicious,
                        detections=pulse_count,
                        total_engines=pulse_count,
                        summary=summary,
                        queried_at=datetime.now(timezone.utc),
                        response_time_ms=elapsed_ms,
                        attributes={
                            "pulse_count": pulse_count,
                            "pulses": top_pulses,
                            "malware_families": sorted(list(malware_families)),
                            "adversaries": sorted(list(adversaries)),
                            "tags": sorted(list(pulse_tags))[:15],
                            "country_name": data.get("country_name"),
                            "asn": data.get("asn")
                        }
                    )

                    # Cache conclusive response
                    provider_cache.set(self.PROVIDER_NAME, indicator_type, indicator, result)
                    return result

                elif response.status_code == 404:
                    result = ProviderResult(
                        provider_name=self.PROVIDER_NAME,
                        status="not_found",
                        summary="Indicator not found in AlienVault OTX threat pulses.",
                        is_malicious=False,
                        detections=0,
                        response_time_ms=elapsed_ms,
                        queried_at=datetime.now(timezone.utc)
                    )
                    provider_cache.set(self.PROVIDER_NAME, indicator_type, indicator, result)
                    return result

                elif response.status_code in (401, 403):
                    # Permanent authentication error: do not retry
                    return ProviderResult(
                        provider_name=self.PROVIDER_NAME,
                        status="unauthorized",
                        summary="AlienVault OTX authentication failed. Verify OTX_API_KEY in .env.",
                        error_message=f"HTTP {response.status_code}: Unauthorized/Forbidden.",
                        response_time_ms=elapsed_ms,
                        queried_at=datetime.now(timezone.utc)
                    )

                elif response.status_code == 429:
                    if attempt < max_attempts - 1:
                        backoff = self._parse_retry_after(response, default=self.base_backoff_seconds * (2 ** attempt))
                        await asyncio.sleep(backoff)
                        continue
                    else:
                        return ProviderResult(
                            provider_name=self.PROVIDER_NAME,
                            status="rate_limited",
                            summary="AlienVault OTX API rate limit exceeded.",
                            error_message="HTTP 429: Rate limit exceeded.",
                            response_time_ms=elapsed_ms,
                            queried_at=datetime.now(timezone.utc)
                        )

                elif response.status_code >= 500:
                    if attempt < max_attempts - 1:
                        backoff = self.base_backoff_seconds * (2 ** attempt)
                        await asyncio.sleep(backoff)
                        continue
                    else:
                        sanitized = self._sanitize_error_text(response.text)
                        return ProviderResult(
                            provider_name=self.PROVIDER_NAME,
                            status="error",
                            summary=f"AlienVault OTX service error (HTTP {response.status_code}).",
                            error_message=f"HTTP {response.status_code}: {sanitized}",
                            response_time_ms=elapsed_ms,
                            queried_at=datetime.now(timezone.utc)
                        )

                else:
                    sanitized = self._sanitize_error_text(response.text)
                    return ProviderResult(
                        provider_name=self.PROVIDER_NAME,
                        status="error",
                        summary=f"AlienVault OTX API returned HTTP status {response.status_code}.",
                        error_message=f"HTTP {response.status_code}: {sanitized}",
                        response_time_ms=elapsed_ms,
                        queried_at=datetime.now(timezone.utc)
                    )

            except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.TimeoutException) as exc:
                if attempt < max_attempts - 1:
                    backoff = self.base_backoff_seconds * (2 ** attempt)
                    await asyncio.sleep(backoff)
                    continue
                return ProviderResult(
                    provider_name=self.PROVIDER_NAME,
                    status="error",
                    summary="Connection to AlienVault OTX API timed out.",
                    error_message=f"Request timeout (>{self.timeout}s). Check network connectivity.",
                    queried_at=datetime.now(timezone.utc)
                )
            except (httpx.ConnectError, httpx.RemoteProtocolError, httpx.RequestError) as exc:
                if attempt < max_attempts - 1:
                    backoff = self.base_backoff_seconds * (2 ** attempt)
                    await asyncio.sleep(backoff)
                    continue
                sanitized_exc = self._sanitize_error_text(str(exc))
                return ProviderResult(
                    provider_name=self.PROVIDER_NAME,
                    status="error",
                    summary="Failed to connect to AlienVault OTX API.",
                    error_message=f"Network error: {sanitized_exc}",
                    queried_at=datetime.now(timezone.utc)
                )
            except Exception as exc:
                sanitized_exc = self._sanitize_error_text(str(exc))
                return ProviderResult(
                    provider_name=self.PROVIDER_NAME,
                    status="error",
                    summary="An unexpected error occurred during AlienVault OTX lookup.",
                    error_message=sanitized_exc,
                    queried_at=datetime.now(timezone.utc)
                )

        return ProviderResult(
            provider_name=self.PROVIDER_NAME,
            status="error",
            summary="AlienVault OTX lookup failed after retries.",
            error_message=last_error_message or "Retries exhausted.",
            queried_at=datetime.now(timezone.utc)
        )

    def _get_endpoint(self, indicator: str, indicator_type: str) -> Optional[str]:
        if indicator_type == "ipv4":
            return f"/indicators/IPv4/{indicator}/general"
        elif indicator_type == "ipv6":
            return f"/indicators/IPv6/{indicator}/general"
        elif indicator_type == "domain":
            return f"/indicators/domain/{indicator}/general"
        elif indicator_type == "url":
            return f"/indicators/url/{indicator}/general"
        elif indicator_type in ("md5", "sha1", "sha256"):
            return f"/indicators/file/{indicator}/general"
        return None
