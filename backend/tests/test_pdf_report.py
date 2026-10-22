import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.models import Investigation
from app.main import app
from app.services.pdf_generator import generate_threat_report_pdf

TEST_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

def test_generate_pdf_report_bytes():
    # Construct an Investigation record with complete attributes
    record = Investigation(
        id="test-uuid-1234-5678",
        indicator="https://evil-phishing-test-site.example.com/very/long/path/to/payload.exe?token=1234567890abcdef",
        normalized_indicator="https://evil-phishing-test-site.example.com/very/long/path/to/payload.exe?token=1234567890abcdef",
        indicator_type="url",
        risk_score=85,
        severity="Critical",
        confidence="High",
        data_coverage="Comprehensive (2/2 Sources)",
        verdict_summary="Critical threat detected (85/100). Malicious URL flagged by multiple antivirus vendors.",
        vt_status="success",
        otx_status="success",
        vt_detections=14,
        vt_total_engines=72,
        otx_pulse_count=3,
        evidence=[
            {"source": "VirusTotal v3", "severity": "critical", "title": "14 AV Engines Flagged", "description": "Flagged as Trojan/Phish."},
            {"source": "AlienVault OTX", "severity": "high", "title": "3 Threat Pulses", "description": "Associated with Campaign Red."},
        ],
        factor_breakdown={
            "virustotal_weight": 0.6,
            "virustotal_score": 85.0,
            "alienvault_weight": 0.4,
            "alienvault_score": 65.0,
            "synergy_boost": 10.0,
            "final_score": 85,
        },
        provider_results={
            "virustotal": {"provider_name": "VirusTotal v3", "status": "success", "summary": "14 detections"},
            "alienvault_otx": {"provider_name": "AlienVault OTX", "status": "success", "summary": "3 pulses", "attributes": {"malware_families": ["RedLine"], "adversaries": ["APT29"]}},
        },
        recommendations=[
            "Block URL at secure web gateway (SWG).",
            "Quarantine any inbound emails containing this URL.",
        ],
        created_at=datetime.now(timezone.utc)
    )

    pdf_bytes = generate_threat_report_pdf(record)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    # PDF signature
    assert pdf_bytes.startswith(b"%PDF")

def test_generate_pdf_with_missing_provider_data():
    # Record when providers are unconfigured
    record = Investigation(
        id="empty-uuid-9999",
        indicator="192.0.2.1",
        normalized_indicator="192.0.2.1",
        indicator_type="ipv4",
        risk_score=0,
        severity="Low",
        confidence="None",
        data_coverage="Unverified (0 Sources Configured/Available)",
        verdict_summary="No threat intelligence providers configured.",
        vt_status="missing_key",
        otx_status="missing_key",
        vt_detections=0,
        vt_total_engines=0,
        otx_pulse_count=0,
        evidence=[],
        factor_breakdown={},
        provider_results={},
        recommendations=["Standard monitoring."],
        created_at=datetime.now(timezone.utc)
    )

    pdf_bytes = generate_threat_report_pdf(record)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")

def test_pdf_endpoint_success_and_headers():
    db = TestingSessionLocal()
    record = Investigation(
        id="pdf-download-id-1",
        indicator="10.0.0.1",
        normalized_indicator="10.0.0.1",
        indicator_type="ipv4",
        risk_score=0,
        severity="Low",
        confidence="None",
        data_coverage="Unverified",
        verdict_summary="Unverified test IP.",
        vt_status="missing_key",
        otx_status="missing_key",
        vt_detections=0,
        vt_total_engines=0,
        otx_pulse_count=0,
        evidence=[],
        factor_breakdown={},
        provider_results={},
        recommendations=["Retain logs."],
        created_at=datetime.now(timezone.utc)
    )
    db.add(record)
    db.commit()
    db.close()

    res = client.get("/api/investigations/pdf-download-id-1/report.pdf")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert "attachment" in res.headers["content-disposition"]
    assert "ThreatLens_Report_pdf-down_10.0.0.1.pdf" in res.headers["content-disposition"]
    assert res.content.startswith(b"%PDF")

def test_pdf_endpoint_not_found_returns_404():
    res = client.get("/api/investigations/non-existent-id/report.pdf")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()
