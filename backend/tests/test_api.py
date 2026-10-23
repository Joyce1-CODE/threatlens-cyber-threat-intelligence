import pytest
from fastapi.testclient import TestClient
from app.main import app
try:
    from tests.conftest import TestingSessionLocal, make_auth_headers
except ImportError:
    from backend.tests.conftest import TestingSessionLocal, make_auth_headers

client = TestClient(app)

def test_health_check_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app_name"] == "ThreatLens AI"

def test_provider_status_endpoint():
    headers = make_auth_headers()
    response = client.get("/api/providers/status", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "virustotal" in data["providers"]
    assert "alienvault_otx" in data["providers"]
    # Check that secrets are not exposed in the response
    assert "api_key" not in str(data).lower()

def test_investigate_ioc_validation_error():
    headers = make_auth_headers()
    # Malformed indicator should return 422
    response = client.post("/api/investigate", json={"indicator": "invalid...ip..address"}, headers=headers)
    assert response.status_code == 422

def test_investigate_valid_ioc_and_persistence():
    headers = make_auth_headers()
    # Valid IOC investigation
    payload = {"indicator": "192.0.2.1", "indicator_type": "ipv4"}
    response = client.post("/api/investigate", json=payload, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["normalized_indicator"] == "192.0.2.1"
    assert data["indicator_type"] == "ipv4"
    assert "risk_score" in data
    assert "evidence" in data

    investigation_id = data["id"]

    # Retrieve details
    detail_res = client.get(f"/api/investigations/{investigation_id}", headers=headers)
    assert detail_res.status_code == 200
    assert detail_res.json()["id"] == investigation_id

    # List investigations
    list_res = client.get("/api/investigations", headers=headers)
    assert list_res.status_code == 200
    list_data = list_res.json()
    assert list_data["total"] >= 1
    assert any(item["id"] == investigation_id for item in list_data["items"])

    # Dashboard stats
    stats_res = client.get("/api/dashboard/stats", headers=headers)
    assert stats_res.status_code == 200
    stats_data = stats_res.json()
    assert stats_data["total_investigations"] >= 1
