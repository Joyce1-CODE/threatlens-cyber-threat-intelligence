import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.main import app

# Test SQLite in-memory database
TEST_DATABASE_URL = "sqlite:///:memory:"
from sqlalchemy.pool import StaticPool
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

def test_health_check_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app_name"] == "ThreatLens AI"

def test_provider_status_endpoint():
    response = client.get("/api/providers/status")
    assert response.status_code == 200
    data = response.json()
    assert "virustotal" in data["providers"]
    assert "alienvault_otx" in data["providers"]
    # Check that secrets are not exposed in the response
    assert "api_key" not in str(data).lower()

def test_investigate_ioc_validation_error():
    # Malformed indicator should return 422
    response = client.post("/api/investigate", json={"indicator": "invalid...ip..address"})
    assert response.status_code == 422

def test_investigate_valid_ioc_and_persistence():
    # Valid IOC investigation
    payload = {"indicator": "192.0.2.1", "indicator_type": "ipv4"}
    response = client.post("/api/investigate", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["normalized_indicator"] == "192.0.2.1"
    assert data["indicator_type"] == "ipv4"
    assert "risk_score" in data
    assert "evidence" in data
    
    investigation_id = data["id"]
    
    # Retrieve details
    detail_res = client.get(f"/api/investigations/{investigation_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["id"] == investigation_id

    # List investigations
    list_res = client.get("/api/investigations")
    assert list_res.status_code == 200
    list_data = list_res.json()
    assert list_data["total"] >= 1
    assert any(item["id"] == investigation_id for item in list_data["items"])

    # Dashboard stats
    stats_res = client.get("/api/dashboard/stats")
    assert stats_res.status_code == 200
    stats_data = stats_res.json()
    assert stats_data["total_investigations"] >= 1
