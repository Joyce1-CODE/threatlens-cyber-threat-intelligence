import asyncio
from datetime import datetime, timezone
from typing import Dict, Any

from app.config import settings
from app.providers.virustotal import VirusTotalProvider
from app.providers.alienvault_otx import AlienVaultOTXProvider
from app.providers.base import ProviderResult
from app.services.risk_engine import RiskScoringEngine

class ThreatAggregator:
    def __init__(self):
        self.vt = VirusTotalProvider(
            api_key=settings.VIRUSTOTAL_API_KEY,
            timeout=settings.REQUEST_TIMEOUT_SECONDS
        )
        self.otx = AlienVaultOTXProvider(
            api_key=settings.OTX_API_KEY,
            timeout=settings.REQUEST_TIMEOUT_SECONDS
        )

    def get_provider_status(self) -> Dict[str, Any]:
        """Returns status of external intelligence providers without exposing secret keys."""
        return {
            "virustotal": {
                "name": "VirusTotal v3",
                "configured": self.vt.is_configured,
                "status": "ready" if self.vt.is_configured else "missing_key",
                "rate_limit_info": "4 requests/min, 500 requests/day (Free tier)",
                "description": "Multi-engine malware scanner and passive DNS intelligence platform."
            },
            "alienvault_otx": {
                "name": "AlienVault OTX",
                "configured": self.otx.is_configured,
                "status": "ready" if self.otx.is_configured else "missing_key",
                "rate_limit_info": "Generous community tier with active threat pulses",
                "description": "Open Threat Exchange community-driven adversary and IOC campaign intelligence."
            }
        }

    async def investigate(self, normalized_indicator: str, indicator_type: str) -> Dict[str, Any]:
        """
        Executes concurrent provider lookups with full error isolation.
        Neither provider failure can block or erase data from the other.
        """
        vt_task = self.vt.lookup(normalized_indicator, indicator_type)
        otx_task = self.otx.lookup(normalized_indicator, indicator_type)
        
        results = await asyncio.gather(vt_task, otx_task, return_exceptions=True)
        
        if isinstance(results[0], Exception):
            vt_result = ProviderResult(
                provider_name=self.vt.PROVIDER_NAME,
                status="error",
                summary="VirusTotal lookup encountered an unhandled exception.",
                error_message=str(results[0]),
                queried_at=datetime.now(timezone.utc)
            )
        else:
            vt_result = results[0]
            
        if isinstance(results[1], Exception):
            otx_result = ProviderResult(
                provider_name=self.otx.PROVIDER_NAME,
                status="error",
                summary="AlienVault OTX lookup encountered an unhandled exception.",
                error_message=str(results[1]),
                queried_at=datetime.now(timezone.utc)
            )
        else:
            otx_result = results[1]
            
        risk_data = RiskScoringEngine.calculate_risk(
            indicator=normalized_indicator,
            indicator_type=indicator_type,
            vt_result=vt_result,
            otx_result=otx_result
        )

        provider_results = {
            "virustotal": vt_result.model_dump(mode="json"),
            "alienvault_otx": otx_result.model_dump(mode="json")
        }

        return {
            **risk_data,
            "vt_status": vt_result.status,
            "otx_status": otx_result.status,
            "vt_detections": vt_result.detections,
            "vt_total_engines": vt_result.total_engines,
            "otx_pulse_count": otx_result.detections,
            "provider_results": provider_results
        }
