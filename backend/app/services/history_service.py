from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, distinct

from app.models import Investigation
from app.schemas import PaginatedInvestigationResponse, InvestigationListItem, DashboardStatsResponse, ProviderStatus

class HistoryService:
    @staticmethod
    def create_investigation(
        db: Session,
        indicator: str,
        normalized_indicator: str,
        indicator_type: str,
        aggregated_data: Dict[str, Any]
    ) -> Investigation:
        record = Investigation(
            indicator=indicator,
            normalized_indicator=normalized_indicator,
            indicator_type=indicator_type,
            risk_score=aggregated_data["risk_score"],
            severity=aggregated_data["severity"],
            confidence=aggregated_data["confidence"],
            data_coverage=aggregated_data["data_coverage"],
            verdict_summary=aggregated_data["verdict_summary"],
            vt_status=aggregated_data["vt_status"],
            otx_status=aggregated_data["otx_status"],
            vt_detections=aggregated_data["vt_detections"],
            vt_total_engines=aggregated_data["vt_total_engines"],
            otx_pulse_count=aggregated_data["otx_pulse_count"],
            evidence=aggregated_data["evidence"],
            factor_breakdown=aggregated_data["factor_breakdown"],
            provider_results=aggregated_data["provider_results"],
            recommendations=aggregated_data["recommendations"]
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    @staticmethod
    def get_by_id(db: Session, investigation_id: str) -> Optional[Investigation]:
        return db.query(Investigation).filter(Investigation.id == investigation_id).first()

    @staticmethod
    def list_investigations(
        db: Session,
        page: int = 1,
        page_size: int = 10,
        search: Optional[str] = None,
        indicator_type: Optional[str] = None,
        severity: Optional[str] = None
    ) -> PaginatedInvestigationResponse:
        query = db.query(Investigation)

        if search:
            search_clean = f"%{search.strip()}%"
            query = query.filter(
                (Investigation.indicator.ilike(search_clean)) |
                (Investigation.normalized_indicator.ilike(search_clean))
            )

        if indicator_type and indicator_type.lower() != "all":
            query = query.filter(Investigation.indicator_type == indicator_type.lower())

        if severity and severity.lower() != "all":
            query = query.filter(Investigation.severity.ilike(severity))

        total = query.count()
        total_pages = max(1, (total + page_size - 1) // page_size)

        records = (
            query.order_by(desc(Investigation.created_at))
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )

        items = [
            InvestigationListItem(
                id=rec.id,
                indicator=rec.indicator,
                normalized_indicator=rec.normalized_indicator,
                indicator_type=rec.indicator_type,
                risk_score=rec.risk_score,
                severity=rec.severity,
                confidence=rec.confidence,
                vt_status=rec.vt_status,
                otx_status=rec.otx_status,
                vt_detections=rec.vt_detections,
                otx_pulse_count=rec.otx_pulse_count,
                created_at=rec.created_at
            )
            for rec in records
        ]

        return PaginatedInvestigationResponse(
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            items=items
        )

    @staticmethod
    def delete_by_id(db: Session, investigation_id: str) -> bool:
        record = db.query(Investigation).filter(Investigation.id == investigation_id).first()
        if record:
            db.delete(record)
            db.commit()
            return True
        return False

    @staticmethod
    def get_dashboard_stats(db: Session, provider_health: Dict[str, Any]) -> DashboardStatsResponse:
        total = db.query(func.count(Investigation.id)).scalar() or 0
        unique = db.query(func.count(distinct(Investigation.normalized_indicator))).scalar() or 0

        # High and Critical count
        high_crit = db.query(func.count(Investigation.id)).filter(
            Investigation.severity.in_(["High", "Critical"])
        ).scalar() or 0

        # Severity breakdown
        severities = ["Low", "Medium", "High", "Critical"]
        sev_counts = {}
        for s in severities:
            count = db.query(func.count(Investigation.id)).filter(
                Investigation.severity.ilike(s)
            ).scalar() or 0
            sev_counts[s] = count

        # Indicator type breakdown
        types = ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"]
        type_counts = {}
        for t in types:
            count = db.query(func.count(Investigation.id)).filter(
                Investigation.indicator_type == t
            ).scalar() or 0
            type_counts[t] = count

        # Recent 5 investigations
        recent_records = (
            db.query(Investigation)
            .order_by(desc(Investigation.created_at))
            .limit(5)
            .all()
        )

        recent_items = [
            InvestigationListItem(
                id=rec.id,
                indicator=rec.indicator,
                normalized_indicator=rec.normalized_indicator,
                indicator_type=rec.indicator_type,
                risk_score=rec.risk_score,
                severity=rec.severity,
                confidence=rec.confidence,
                vt_status=rec.vt_status,
                otx_status=rec.otx_status,
                vt_detections=rec.vt_detections,
                otx_pulse_count=rec.otx_pulse_count,
                created_at=rec.created_at
            )
            for rec in recent_records
        ]

        health_objs = {
            k: ProviderStatus(**v) for k, v in provider_health.items()
        }

        return DashboardStatsResponse(
            total_investigations=total,
            unique_indicators=unique,
            high_critical_count=high_crit,
            severity_breakdown=sev_counts,
            indicator_type_breakdown=type_counts,
            provider_health=health_objs,
            recent_investigations=recent_items
        )
