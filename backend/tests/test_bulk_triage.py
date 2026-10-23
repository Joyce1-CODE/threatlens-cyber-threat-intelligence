import io
import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient

from app.main import app
from app.services.bulk_service import BulkService, BulkServiceError
try:
    from tests.conftest import TestingSessionLocal, make_auth_headers
except ImportError:
    from backend.tests.conftest import TestingSessionLocal, make_auth_headers

client = TestClient(app)

def test_csv_preview_valid():
    csv_data = b"indicator,source,notes\n8.8.8.8,DNS,Google Public DNS\nevil[.]com,Phish,Defanged domain\n1.1.1.1,DNS,Cloudflare\n"
    preview = BulkService.preview_csv_content(csv_data, "test.csv")
    assert preview["total_rows"] == 3
    assert preview["valid_count"] == 3
    assert preview["detected_column"] == "indicator"
    assert len(preview["items"]) == 3
    assert preview["items"][0]["normalized"] == "8.8.8.8"
    assert preview["items"][1]["normalized"] == "evil.com"
    assert preview["items"][1]["type"] == "domain"

def test_csv_preview_with_invalid_and_duplicates():
    csv_data = b"ioc\n8.8.8.8\n8.8.8.8\nnot_valid_indicator!!!\n2001:db8::1\n"
    preview = BulkService.preview_csv_content(csv_data, "sample.csv")
    assert preview["total_rows"] == 4
    assert preview["valid_count"] == 2 # 8.8.8.8 and ipv6
    assert preview["duplicate_count"] == 1 # Second 8.8.8.8
    assert preview["invalid_count"] == 1 # not_valid_indicator!!!

    invalid_item = next(it for it in preview["items"] if not it["is_valid"])
    assert invalid_item["error"] is not None

def test_csv_preview_rejects_empty():
    with pytest.raises(BulkServiceError):
        BulkService.preview_csv_content(b"", "empty.csv")

def test_csv_preview_endpoint():
    headers = make_auth_headers()
    csv_content = b"indicator\n198.51.100.1\n93.184.216.34\n"
    files = {"file": ("test_iocs.csv", csv_content, "text/csv")}
    res = client.post("/api/bulk/preview", files=files, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["valid_count"] == 2
    assert data["filename"] == "test_iocs.csv"

def test_csv_preview_endpoint_rejects_non_csv():
    headers = make_auth_headers()
    files = {"file": ("malware.exe", b"MZ...", "application/octet-stream")}
    res = client.post("/api/bulk/preview", files=files, headers=headers)
    assert res.status_code == 400
    assert "unsupported" in res.json()["detail"].lower()

@pytest.mark.asyncio
async def test_bulk_triage_execution_and_persistence():
    headers = make_auth_headers()
    payload = {
        "items": [
            {"indicator": "8.8.8.8", "indicator_type": "ipv4"},
            {"indicator": "invalid...syntax", "indicator_type": "auto"}
        ]
    }
    res = client.post("/api/bulk/triage", json=payload, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total_submitted"] == 2
    assert data["completed"] == 1
    assert data["invalid"] == 1
    assert len(data["results"]) == 2

    valid_res = next(r for r in data["results"] if r["status"] == "completed")
    assert valid_res["id"] is not None
    assert valid_res["normalized_indicator"] == "8.8.8.8"

    invalid_res = next(r for r in data["results"] if r["status"] == "invalid")
    assert invalid_res["id"] is None
    assert "Validation Error" in invalid_res["verdict_summary"]

def test_bulk_export_csv():
    headers = make_auth_headers()
    mock_results = [
        {
            "id": "exp-1",
            "indicator": "1.1.1.1",
            "normalized_indicator": "1.1.1.1",
            "indicator_type": "ipv4",
            "risk_score": 0,
            "severity": "Low",
            "confidence": "High",
            "data_coverage": "2/2 Sources",
            "vt_status": "clean",
            "vt_detections": 0,
            "otx_status": "clean",
            "otx_pulse_count": 0,
            "status": "completed",
            "verdict_summary": "Clean IP.",
            "created_at": "2026-10-22T10:00:00",
        }
    ]
    res = client.post("/api/bulk/export", json={"results": mock_results}, headers=headers)
    assert res.status_code == 200
    assert res.headers["content-type"] == "text/csv; charset=utf-8"
    assert "attachment" in res.headers["content-disposition"]
    csv_body = res.text
    assert "Original Indicator" in csv_body
    assert "1.1.1.1" in csv_body
    assert "Clean IP." in csv_body
