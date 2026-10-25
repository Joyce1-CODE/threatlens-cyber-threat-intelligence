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

def test_database_url_normalization_and_psycopg2_dialect():
    from app.database import normalize_database_url
    from sqlalchemy import create_engine

    # 1. Test legacy postgres:// normalization
    u1 = "postgres://user:pass@host:5432/threatlens?sslmode=require"
    n1 = normalize_database_url(u1)
    assert n1.startswith("postgresql+psycopg2://")
    e1 = create_engine(n1)
    assert e1.dialect.name == "postgresql"
    assert e1.dialect.driver == "psycopg2"

    # 2. Test unadorned postgresql:// normalization
    u2 = "postgresql://user:pass@host:5432/threatlens"
    n2 = normalize_database_url(u2)
    assert n2.startswith("postgresql+psycopg2://")
    e2 = create_engine(n2)
    assert e2.dialect.name == "postgresql"
    assert e2.dialect.driver == "psycopg2"

    # 3. Test explicit driver preservation
    u3 = "postgresql+psycopg2://user:pass@host:5432/threatlens"
    n3 = normalize_database_url(u3)
    assert n3 == u3

    u4 = "postgresql+asyncpg://user:pass@host:5432/threatlens"
    n4 = normalize_database_url(u4)
    assert n4 == u4

    # 4. Test SQLite preservation
    u5 = "sqlite:///./threatlens.db"
    n5 = normalize_database_url(u5)
    assert n5 == u5
    e5 = create_engine(n5)
    assert e5.dialect.name == "sqlite"
    assert e5.dialect.driver == "pysqlite"

def test_cors_origins_json_array_input(monkeypatch):
    from app.config import Settings
    monkeypatch.setenv("CORS_ORIGINS", '["https://threatlens.vercel.app", "http://localhost:5173"]')
    s = Settings()
    assert s.CORS_ORIGINS == ["https://threatlens.vercel.app", "http://localhost:5173"]

def test_cors_origins_comma_separated_input(monkeypatch):
    from app.config import Settings
    monkeypatch.setenv("CORS_ORIGINS", "https://threatlens.vercel.app,http://localhost:5173")
    s = Settings()
    assert s.CORS_ORIGINS == ["https://threatlens.vercel.app", "http://localhost:5173"]

def test_cors_origins_single_origin_input(monkeypatch):
    from app.config import Settings
    monkeypatch.setenv("CORS_ORIGINS", "https://threatlens.vercel.app")
    s = Settings()
    assert s.CORS_ORIGINS == ["https://threatlens.vercel.app"]

def test_cors_origins_trailing_slash_normalization(monkeypatch):
    from app.config import Settings
    monkeypatch.setenv("CORS_ORIGINS", "https://threatlens.vercel.app/ , http://localhost:5173/")
    s = Settings()
    assert s.CORS_ORIGINS == ["https://threatlens.vercel.app", "http://localhost:5173"]

def test_cors_origins_empty_and_whitespace_input(monkeypatch):
    from app.config import Settings
    monkeypatch.setenv("CORS_ORIGINS", "")
    s1 = Settings()
    assert s1.CORS_ORIGINS == []

    monkeypatch.setenv("CORS_ORIGINS", "   ")
    s2 = Settings()
    assert s2.CORS_ORIGINS == []

    monkeypatch.setenv("CORS_ORIGINS", "[]")
    s3 = Settings()
    assert s3.CORS_ORIGINS == []

def test_cors_origins_wildcard_rejected_for_credentials(monkeypatch):
    from app.config import Settings
    # Wildcard '*' must be stripped to prevent CORS credential vulnerability
    monkeypatch.setenv("CORS_ORIGINS", "*,https://threatlens.vercel.app")
    s = Settings()
    assert s.CORS_ORIGINS == ["https://threatlens.vercel.app"]
    assert "*" not in s.CORS_ORIGINS
