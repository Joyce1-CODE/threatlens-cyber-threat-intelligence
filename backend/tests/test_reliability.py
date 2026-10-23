import pytest
import asyncio
from unittest.mock import patch, AsyncMock
import httpx

from app.providers.virustotal import VirusTotalProvider
from app.providers.alienvault_otx import AlienVaultOTXProvider
from app.providers.cache import provider_cache, ProviderCache
from app.services.rate_limiter import ProviderRateLimiter
from app.services.aggregator import ThreatAggregator
from app.services.bulk_service import BulkService
from app.database import Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

@pytest.fixture(autouse=True)
def clear_cache():
    provider_cache.clear()
    yield
    provider_cache.clear()

@pytest.mark.asyncio
async def test_virustotal_unauthorized_permanent_error_no_retry():
    vt = VirusTotalProvider(api_key="invalid_vt_key", max_retries=2, base_backoff_seconds=0.01)
    mock_resp = httpx.Response(401, text="Forbidden / Invalid API Key", request=httpx.Request("GET", "https://mock.com"))

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await vt.lookup("8.8.8.8", "ipv4")

        # Verify it was queried exactly once (no retry on 401)
        assert mock_get.call_count == 1
        assert res.status == "unauthorized"
        assert "authentication failed" in res.summary.lower()

@pytest.mark.asyncio
async def test_virustotal_retry_after_header_handling():
    vt = VirusTotalProvider(api_key="mock_vt_key", max_retries=1, base_backoff_seconds=0.01, max_backoff_seconds=0.1)

    # 1st response: 429 with Retry-After: 0.05
    # 2nd response: 200 OK
    resp_429 = httpx.Response(
        429,
        text="Rate limited",
        headers={"retry-after": "0.05"},
        request=httpx.Request("GET", "https://mock.com")
    )
    resp_200 = httpx.Response(
        200,
        json={"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 70}, "reputation": 10}}},
        request=httpx.Request("GET", "https://mock.com")
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = [resp_429, resp_200]
        res = await vt.lookup("1.1.1.1", "ipv4")

        assert mock_get.call_count == 2
        assert res.status == "clean"
        assert res.detections == 0

@pytest.mark.asyncio
async def test_virustotal_transient_503_retry_success():
    vt = VirusTotalProvider(api_key="mock_vt_key", max_retries=2, base_backoff_seconds=0.01)
    resp_503 = httpx.Response(503, text="Service Unavailable", request=httpx.Request("GET", "https://mock.com"))
    resp_200 = httpx.Response(
        200,
        json={"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 60}}}},
        request=httpx.Request("GET", "https://mock.com")
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = [resp_503, resp_200]
        res = await vt.lookup("phishing.site", "domain")

        assert mock_get.call_count == 2
        assert res.status == "success"
        assert res.detections == 3

@pytest.mark.asyncio
async def test_virustotal_timeout_retries_exhausted():
    vt = VirusTotalProvider(api_key="mock_vt_key", max_retries=2, base_backoff_seconds=0.01)

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = httpx.ReadTimeout("Read timed out")
        res = await vt.lookup("slow.target.com", "domain")

        # Initial attempt + 2 retries = 3 attempts
        assert mock_get.call_count == 3
        assert res.status == "error"
        assert "timed out" in res.summary.lower()

@pytest.mark.asyncio
async def test_provider_caching_behavior():
    vt = VirusTotalProvider(api_key="mock_vt_key", max_retries=1)
    resp_200 = httpx.Response(
        200,
        json={"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 70}}}},
        request=httpx.Request("GET", "https://mock.com")
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = resp_200
        # 1st lookup: external call
        res1 = await vt.lookup("8.8.4.4", "ipv4")
        assert mock_get.call_count == 1
        assert res1.cached is False

        # 2nd lookup: cache hit
        res2 = await vt.lookup("8.8.4.4", "ipv4")
        assert mock_get.call_count == 1 # No additional HTTP call
        assert res2.cached is True
        assert res2.status == "clean"

@pytest.mark.asyncio
async def test_alienvault_otx_unauthorized_permanent_error():
    otx = AlienVaultOTXProvider(api_key="bad_otx_key", max_retries=2, base_backoff_seconds=0.01)
    mock_resp = httpx.Response(403, text="Invalid API key", request=httpx.Request("GET", "https://mock.com"))

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await otx.lookup("8.8.8.8", "ipv4")

        assert mock_get.call_count == 1
        assert res.status == "unauthorized"
        assert "authentication failed" in res.summary.lower()

@pytest.mark.asyncio
async def test_alienvault_otx_transient_error_retry_success():
    otx = AlienVaultOTXProvider(api_key="mock_otx_key", max_retries=2, base_backoff_seconds=0.01)
    resp_500 = httpx.Response(500, text="Internal Server Error", request=httpx.Request("GET", "https://mock.com"))
    resp_200 = httpx.Response(
        200,
        json={"pulse_info": {"count": 2, "pulses": [{"name": "APT Pulse", "tags": ["apt"]}]}},
        request=httpx.Request("GET", "https://mock.com")
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = [resp_500, resp_200]
        res = await otx.lookup("104.244.42.1", "ipv4")

        assert mock_get.call_count == 2
        assert res.status == "success"
        assert res.detections == 2

@pytest.mark.asyncio
async def test_rate_limiter_circuit_breaker():
    limiter = ProviderRateLimiter(vt_interval_seconds=0.0, otx_interval_seconds=0.0)

    # Initially healthy
    assert await limiter.acquire_vt() is True

    # Mark rate limited
    limiter.mark_vt_rate_limited(cooldown_seconds=300.0)

    # Should now reject calls until cooldown expires
    assert await limiter.acquire_vt() is False

    # OTX remains independent and healthy
    assert await limiter.acquire_otx() is True

@pytest.mark.asyncio
async def test_bulk_triage_handles_rate_limited_provider_without_failing_batch():
    test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    test_session = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    db = test_session()

    items = [
        {"indicator": "1.1.1.1", "indicator_type": "ipv4"},
        {"indicator": "2.2.2.2", "indicator_type": "ipv4"},
    ]

    # Mock VT to return 429 rate limit on first call, OTX returns 200 OK
    resp_vt_429 = httpx.Response(429, text="Rate limit exceeded", request=httpx.Request("GET", "https://mock.com"))
    resp_otx_200 = httpx.Response(200, json={"pulse_info": {"count": 0, "pulses": []}}, request=httpx.Request("GET", "https://mock.com"))

    limiter = ProviderRateLimiter(vt_interval_seconds=0.0, otx_interval_seconds=0.0)

    async def mock_get(url, *args, **kwargs):
        if "virustotal.com" in str(url):
            return resp_vt_429
        elif "alienvault.com" in str(url):
            return resp_otx_200
        return httpx.Response(200, json={}, request=httpx.Request("GET", "https://mock.com"))

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        with patch("app.providers.virustotal.VirusTotalProvider.is_configured", True):
            with patch("app.providers.alienvault_otx.AlienVaultOTXProvider.is_configured", True):
                batch_res = await BulkService.process_batch_triage(
                    items=items,
                    db=db,
                    concurrency=1,
                    rate_limiter=limiter
                )

    assert batch_res["completed"] == 2
    assert batch_res["rate_limited_count"] >= 1
    # Check that OTX succeeded even though VT hit 429
    for r in batch_res["results"]:
        assert r["otx_status"] == "clean"
        assert r["vt_status"] == "rate_limited"

def test_api_key_redaction_in_sanitization():
    secret_key = "secret_apikey_1234567890abcdef123456"
    vt = VirusTotalProvider(api_key=secret_key)

    leak_text = f"Connection failed with key {secret_key} on endpoint"
    sanitized = vt._sanitize_error_text(leak_text)

    assert secret_key not in sanitized
    assert "[REDACTED_API_KEY]" in sanitized
