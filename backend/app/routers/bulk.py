import re
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.services.bulk_service import BulkService, BulkServiceError
from app.services.auth_service import require_analyst, require_authenticated

router = APIRouter(prefix="/bulk", tags=["Bulk IOC Triage"])

class BulkTargetItem(BaseModel):
    indicator: str = Field(..., min_length=1, max_length=2048)
    indicator_type: Optional[str] = "auto"

class BulkTriageRequest(BaseModel):
    items: List[BulkTargetItem] = Field(..., max_length=50)

class BulkExportRequest(BaseModel):
    results: List[Dict[str, Any]]

@router.post("/preview")
async def preview_csv_upload(
    file: UploadFile = File(...),
    current_user: User = Depends(require_analyst)
):
    # Verify file extension
    filename = file.filename or "upload.csv"
    if not (filename.lower().endswith(".csv") or filename.lower().endswith(".txt")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file format. Please upload a standard CSV or TXT file."
        )

    try:
        content_bytes = await file.read()
        preview = BulkService.preview_csv_content(content_bytes, filename=filename)
        return preview
    except BulkServiceError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err)
        )
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error parsing CSV file: {str(err)}"
        )

@router.post("/triage")
async def execute_bulk_triage(
    payload: BulkTriageRequest,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db)
):
    if not payload.items:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Batch list cannot be empty."
        )

    items_dict = [{"indicator": it.indicator, "indicator_type": it.indicator_type or "auto"} for it in payload.items]
    triage_result = await BulkService.process_batch_triage(items_dict, db=db, concurrency=4)
    return triage_result

@router.post("/export")
def export_bulk_results_csv(
    payload: BulkExportRequest,
    current_user: User = Depends(require_authenticated)
):
    if not payload.results:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No results provided for export."
        )

    csv_text = BulkService.generate_results_csv(payload.results)
    return Response(
        content=csv_text.encode("utf-8"),
        media_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="ThreatLens_Bulk_Triage_Results.csv"'
        }
    )
