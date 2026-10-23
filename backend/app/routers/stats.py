from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import DashboardStatsResponse
from app.services.aggregator import ThreatAggregator
from app.services.history_service import HistoryService
from app.services.auth_service import require_authenticated

router = APIRouter(prefix="", tags=["Dashboard Statistics"])
aggregator = ThreatAggregator()

@router.get("/dashboard/stats", response_model=DashboardStatsResponse)
def get_dashboard_statistics(
    current_user: User = Depends(require_authenticated),
    db: Session = Depends(get_db)
):
    health_info = aggregator.get_provider_status()
    return HistoryService.get_dashboard_stats(db=db, provider_health=health_info)
