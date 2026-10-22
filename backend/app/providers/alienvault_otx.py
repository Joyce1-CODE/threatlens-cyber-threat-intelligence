from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import httpx

from app.providers.base import BaseThreatProvider, ProviderResult

class AlienVaultOTXProvider(BaseThreatProvider):
    PROVIDER_NAME = "AlienVault OTX"
    BASE_URL = "https://otx.alienvault.com/api/v1"
    
    async def lookup(self, indicator: str, indicator_type: str) -> ProviderResult:
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
            
        headers = {
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json",
            "User-Agent": "ThreatLens-AI/1.0"
        }
        
        url = f"{self.BASE_URL}{endpoint}"
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url, headers=headers)
                
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
                
                return ProviderResult(
                    provider_name=self.PROVIDER_NAME,
                    status="success" if pulse_count > 0 else "clean",
                    is_malicious=is_malicious,
                    detections=pulse_count,
                    total_engines=pulse_count, # Represents community pulse sightings
                    summary=summary,
                    queried_at=datetime.now(timezone.utc),
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
                
            elif response.status_code == 404:
                return ProviderResult(
                    provider_name=self.PROVIDER_NAME,
                    status="not_found",
                    summary="Indicator not found in AlienVault OTX threat pulses.",
                    is_malicious=False,
                    detections=0,
                    queried_at=datetime.now(timezone.utc)
                )
                
            elif response.status_code in (401, 403):
                return ProviderResult(
                    provider_name=self.PROVIDER_NAME,
                    status="unauthorized",
                    summary="AlienVault OTX authentication failed. Verify OTX_API_KEY in .env.",
                    error_message=f"HTTP {response.status_code}: Unauthorized/Forbidden.",
                    queried_at=datetime.now(timezone.utc)
                )
                
            elif response.status_code == 429:
                return ProviderResult(
                    provider_name=self.PROVIDER_NAME,
                    status="rate_limited",
                    summary="AlienVault OTX API rate limit exceeded.",
                    error_message="HTTP 429: Rate limit exceeded.",
                    queried_at=datetime.now(timezone.utc)
                )
                
            else:
                return ProviderResult(
                    provider_name=self.PROVIDER_NAME,
                    status="error",
                    summary=f"AlienVault OTX API returned HTTP status {response.status_code}.",
                    error_message=f"HTTP {response.status_code}: {response.text[:200]}",
                    queried_at=datetime.now(timezone.utc)
                )
                
        except httpx.TimeoutException:
            return ProviderResult(
                provider_name=self.PROVIDER_NAME,
                status="error",
                summary="Connection to AlienVault OTX API timed out.",
                error_message="Request timeout (>12s). Check internet connection.",
                queried_at=datetime.now(timezone.utc)
            )
        except httpx.RequestError as exc:
            return ProviderResult(
                provider_name=self.PROVIDER_NAME,
                status="error",
                summary="Failed to connect to AlienVault OTX API.",
                error_message=f"Network error: {str(exc)}",
                queried_at=datetime.now(timezone.utc)
            )
        except Exception as exc:
            return ProviderResult(
                provider_name=self.PROVIDER_NAME,
                status="error",
                summary="An unexpected error occurred during AlienVault OTX lookup.",
                error_message=str(exc),
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
