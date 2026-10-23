import base64
import time
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import httpx

from app.providers.base import BaseThreatProvider, ProviderResult
from app.providers.cache import provider_cache

class VirusTotalProvider(BaseThreatProvider):
    PROVIDER_NAME = "VirusTotal v3"
    BASE_URL = "https://www.virustotal.com/api/v3"

    async def lookup(self, indicator: str, indicator_type: str, use_cache: bool = True) -> ProviderResult:
        if not self.is_configured:
            return ProviderResult(
                provider_name=self.PROVIDER_NAME,
                status="missing_key",
                summary="VirusTotal API key not configured. Add VIRUSTOTAL_API_KEY to .env.",
                error_message="Missing API credentials in environment.",
                queried_at=datetime.now(timezone.utc)
            )

        endpoint = self._get_endpoint(indicator, indicator_type)
        if not endpoint:
            return ProviderResult(
                provider_name=self.PROVIDER_NAME,
                status="unsupported",
                summary=f"Indicator type '{indicator_type}' is not supported by VirusTotal integration.",
                error_message="Unsupported IOC type",
                queried_at=datetime.now(timezone.utc)
            )

        # Check in-memory cache first
        if use_cache:
            cached_result = provider_cache.get(self.PROVIDER_NAME, indicator_type, indicator)
            if cached_result:
                return cached_result

        headers = {
            "x-apikey": self.api_key,
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
                    data = response.json().get("data", {})
                    attributes = data.get("attributes", {})

                    stats = attributes.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                    total_engines = malicious + suspicious + harmless + undetected

                    reputation = attributes.get("reputation", 0)
                    tags = attributes.get("tags", [])

                    # Extract notable vendor engine verdicts
                    engine_results = attributes.get("last_analysis_results", {})
                    flagged_engines = [
                        {"engine": name, "category": details.get("category"), "result": details.get("result")}
                        for name, details in engine_results.items()
                        if details.get("category") in ("malicious", "suspicious")
                    ]

                    is_malicious = (malicious > 0 or suspicious > 1)

                    summary = (
                        f"VirusTotal detected {malicious} malicious and {suspicious} suspicious engine verdicts "
                        f"out of {total_engines} total engines evaluated."
                    ) if total_engines > 0 else "VirusTotal analysis completed with no engine stats."

                    # Additional contextual attributes
                    extra_attrs = {}
                    if "as_owner" in attributes:
                        extra_attrs["as_owner"] = attributes.get("as_owner")
                    if "country" in attributes:
                        extra_attrs["country"] = attributes.get("country")
                    if "network" in attributes:
                        extra_attrs["network"] = attributes.get("network")
                    if "categories" in attributes:
                        extra_attrs["categories"] = attributes.get("categories")
                    if "names" in attributes:
                        extra_attrs["names"] = attributes.get("names")[:5]

                    result = ProviderResult(
                        provider_name=self.PROVIDER_NAME,
                        status="success" if malicious > 0 else "clean",
                        is_malicious=is_malicious,
                        detections=malicious,
                        total_engines=total_engines,
                        reputation_score=float(reputation),
                        summary=summary,
                        queried_at=datetime.now(timezone.utc),
                        response_time_ms=elapsed_ms,
                        attributes={
                            "stats": stats,
                            "reputation": reputation,
                            "tags": tags,
                            "flagged_engines": flagged_engines[:10],
                            "last_analysis_date": attributes.get("last_analysis_date"),
                            **extra_attrs
                        }
                    )

                    # Cache conclusive response
                    provider_cache.set(self.PROVIDER_NAME, indicator_type, indicator, result)
                    return result

                elif response.status_code == 404:
                    result = ProviderResult(
                        provider_name=self.PROVIDER_NAME,
                        status="not_found",
                        summary="Indicator not found in VirusTotal database (no prior observations or scans recorded).",
                        is_malicious=False,
                        detections=0,
                        total_engines=0,
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
                        summary="VirusTotal authentication failed. Verify VIRUSTOTAL_API_KEY in .env.",
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
                            summary="VirusTotal request rate limit reached. Public API allows 4 requests/min.",
                            error_message="HTTP 429: Quota exceeded / Rate limited.",
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
                            summary=f"VirusTotal service error (HTTP {response.status_code}).",
                            error_message=f"HTTP {response.status_code}: {sanitized}",
                            response_time_ms=elapsed_ms,
                            queried_at=datetime.now(timezone.utc)
                        )

                else:
                    sanitized = self._sanitize_error_text(response.text)
                    return ProviderResult(
                        provider_name=self.PROVIDER_NAME,
                        status="error",
                        summary=f"VirusTotal API returned HTTP status {response.status_code}.",
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
                    summary="Connection to VirusTotal API timed out.",
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
                    summary="Failed to connect to VirusTotal API.",
                    error_message=f"Network error: {sanitized_exc}",
                    queried_at=datetime.now(timezone.utc)
                )
            except Exception as exc:
                sanitized_exc = self._sanitize_error_text(str(exc))
                return ProviderResult(
                    provider_name=self.PROVIDER_NAME,
                    status="error",
                    summary="An unexpected error occurred during VirusTotal lookup.",
                    error_message=sanitized_exc,
                    queried_at=datetime.now(timezone.utc)
                )

        # Fallback if loop exits without returning
        return ProviderResult(
            provider_name=self.PROVIDER_NAME,
            status="error",
            summary="VirusTotal lookup failed after retries.",
            error_message=last_error_message or "Retries exhausted.",
            queried_at=datetime.now(timezone.utc)
        )

    def _get_endpoint(self, indicator: str, indicator_type: str) -> Optional[str]:
        if indicator_type in ("ipv4", "ipv6"):
            return f"/ip_addresses/{indicator}"
        elif indicator_type == "domain":
            return f"/domains/{indicator}"
        elif indicator_type in ("md5", "sha1", "sha256"):
            return f"/files/{indicator}"
        elif indicator_type == "url":
            # VT v3 URL identifier is URL-safe base64 without padding
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
            return f"/urls/{url_id}"
        return None
