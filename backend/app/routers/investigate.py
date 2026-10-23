import re
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import (
    IOCInvestigationRequest,
    InvestigationResponse,
    PaginatedInvestigationResponse
)
from app.ioc_validator import validate_and_normalize_ioc, IOCValidationError
from app.services.aggregator import ThreatAggregator
from app.services.history_service import HistoryService
from app.services.pdf_generator import generate_threat_report_pdf
from app.services.auth_service import require_analyst, require_authenticated, require_admin

router = APIRouter(prefix="", tags=["IOC Investigation"])
aggregator = ThreatAggregator()

@router.post("/investigate", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
async def investigate_ioc(
    payload: IOCInvestigationRequest,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db)
):
    try:
        normalized_indicator, detected_type = validate_and_normalize_ioc(
            payload.indicator,
            payload.indicator_type
        )
    except IOCValidationError as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"message": str(err), "field": err.field}
        )

    # Perform concurrent threat intelligence lookup
    aggregated_data = await aggregator.investigate(normalized_indicator, detected_type)

    # Persist investigation
    record = HistoryService.create_investigation(
        db=db,
        indicator=payload.indicator.strip(),
        normalized_indicator=normalized_indicator,
        indicator_type=detected_type,
        aggregated_data=aggregated_data
    )

    return record

@router.get("/investigations", response_model=PaginatedInvestigationResponse)
def list_investigations(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(None, description="Search indicator string"),
    indicator_type: Optional[str] = Query(None, description="Filter by type (ipv4, domain, etc.)"),
    severity: Optional[str] = Query(None, description="Filter by severity (Low, Medium, High, Critical)"),
    current_user: User = Depends(require_authenticated),
    db: Session = Depends(get_db)
):
    return HistoryService.list_investigations(
        db=db,
        page=page,
        page_size=page_size,
        search=search,
        indicator_type=indicator_type,
        severity=severity
    )

@router.get("/investigations/{investigation_id}", response_model=InvestigationResponse)
def get_investigation_details(
    investigation_id: str,
    current_user: User = Depends(require_authenticated),
    db: Session = Depends(get_db)
):
    record = HistoryService.get_by_id(db, investigation_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{investigation_id}' was not found."
        )
    return record

@router.get("/investigations/{investigation_id}/report.pdf")
def download_investigation_report_pdf(
    investigation_id: str,
    current_user: User = Depends(require_authenticated),
    db: Session = Depends(get_db)
):
    record = HistoryService.get_by_id(db, investigation_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{investigation_id}' was not found."
        )

    pdf_bytes = generate_threat_report_pdf(record)

    # Sanitize indicator for safe ASCII filename
    safe_indicator = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", record.normalized_indicator)[:40]
    filename = f"ThreatLens_Report_{record.id[:8]}_{safe_indicator}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )

@router.delete("/investigations/{investigation_id}", status_code=status.HTTP_200_OK)
def delete_investigation(
    investigation_id: str,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    success = HistoryService.delete_by_id(db, investigation_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{investigation_id}' was not found."
        )
    return {"status": "deleted", "id": investigation_id}
