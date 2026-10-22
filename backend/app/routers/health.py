from datetime import datetime, timezone
from fastapi import APIRouter
from app.schemas import SystemStatusResponse, ProviderStatus
from app.services.aggregator import ThreatAggregator

router = APIRouter(prefix="", tags=["System & Providers"])
aggregator = ThreatAggregator()

@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "app_name": "ThreatLens AI",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc)
    }

@router.get("/providers/status", response_model=SystemStatusResponse)
def get_providers_status():
    provider_info = aggregator.get_provider_status()
    providers = {k: ProviderStatus(**v) for k, v in provider_info.items()}
    return SystemStatusResponse(
        app_name="ThreatLens AI",
        version="1.0.0",
        status="operational",
        timestamp=datetime.now(timezone.utc),
        providers=providers
    )
