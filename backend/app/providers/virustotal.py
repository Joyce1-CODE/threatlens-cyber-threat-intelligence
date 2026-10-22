import base64
from datetime import datetime, timezone
from typing import Dict, Any
import httpx

from app.providers.base import BaseThreatProvider, ProviderResult

class VirusTotalProvider(BaseThreatProvider):
    PROVIDER_NAME = "VirusTotal v3"
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    async def lookup(self, indicator: str, indicator_type: str) -> ProviderResult:
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
            
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "User-Agent": "ThreatLens-AI/1.0"
        }
        
        url = f"{self.BASE_URL}{endpoint}"
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url, headers=headers)
                
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
                
                return ProviderResult(
                    provider_name=self.PROVIDER_NAME,
                    status="success" if malicious > 0 else "clean",
                    is_malicious=is_malicious,
                    detections=malicious,
                    total_engines=total_engines,
                    reputation_score=float(reputation),
                    summary=summary,
                    queried_at=datetime.now(timezone.utc),
                    attributes={
                        "stats": stats,
                        "reputation": reputation,
                        "tags": tags,
                        "flagged_engines": flagged_engines[:10], # Top 10 flagged engines
                        "last_analysis_date": attributes.get("last_analysis_date")
                    }
                )
                
            elif response.status_code == 404:
                return ProviderResult(
                    provider_name=self.PROVIDER_NAME,
                    status="not_found",
                    summary="Indicator not found in VirusTotal database (no prior observations or scans recorded).",
                    is_malicious=False,
                    detections=0,
                    total_engines=0,
                    queried_at=datetime.now(timezone.utc)
                )
                
            elif response.status_code in (401, 403):
                return ProviderResult(
                    provider_name=self.PROVIDER_NAME,
                    status="unauthorized",
                    summary="VirusTotal authentication failed. Verify VIRUSTOTAL_API_KEY in .env.",
                    error_message=f"HTTP {response.status_code}: Unauthorized/Forbidden.",
                    queried_at=datetime.now(timezone.utc)
                )
                
            elif response.status_code == 429:
                return ProviderResult(
                    provider_name=self.PROVIDER_NAME,
                    status="rate_limited",
                    summary="VirusTotal request rate limit reached. Public API allows 4 requests/min.",
                    error_message="HTTP 429: Quota exceeded / Rate limited.",
                    queried_at=datetime.now(timezone.utc)
                )
                
            else:
                return ProviderResult(
                    provider_name=self.PROVIDER_NAME,
                    status="error",
                    summary=f"VirusTotal API returned HTTP status {response.status_code}.",
                    error_message=f"HTTP {response.status_code}: {response.text[:200]}",
                    queried_at=datetime.now(timezone.utc)
                )
                
        except httpx.TimeoutException:
            return ProviderResult(
                provider_name=self.PROVIDER_NAME,
                status="error",
                summary="Connection to VirusTotal API timed out.",
                error_message="Request timeout (>12s). Check internet connection.",
                queried_at=datetime.now(timezone.utc)
            )
        except httpx.RequestError as exc:
            return ProviderResult(
                provider_name=self.PROVIDER_NAME,
                status="error",
                summary="Failed to connect to VirusTotal API.",
                error_message=f"Network error: {str(exc)}",
                queried_at=datetime.now(timezone.utc)
            )
        except Exception as exc:
            return ProviderResult(
                provider_name=self.PROVIDER_NAME,
                status="error",
                summary="An unexpected error occurred during VirusTotal lookup.",
                error_message=str(exc),
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
