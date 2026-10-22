from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import (
    IOCInvestigationRequest,
    InvestigationResponse,
    PaginatedInvestigationResponse
)
from app.ioc_validator import validate_and_normalize_ioc, IOCValidationError
from app.services.aggregator import ThreatAggregator
from app.services.history_service import HistoryService

router = APIRouter(prefix="", tags=["IOC Investigation"])
aggregator = ThreatAggregator()

@router.post("/investigate", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
async def investigate_ioc(
    payload: IOCInvestigationRequest,
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
    db: Session = Depends(get_db)
):
    record = HistoryService.get_by_id(db, investigation_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{investigation_id}' was not found."
        )
    return record

@router.delete("/investigations/{investigation_id}", status_code=status.HTTP_200_OK)
def delete_investigation(
    investigation_id: str,
    db: Session = Depends(get_db)
):
    success = HistoryService.delete_by_id(db, investigation_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{investigation_id}' was not found."
        )
    return {"status": "deleted", "id": investigation_id}
