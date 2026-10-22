import pytest
from unittest.mock import patch, AsyncMock
import httpx
from app.providers.virustotal import VirusTotalProvider
from app.providers.alienvault_otx import AlienVaultOTXProvider

@pytest.mark.asyncio
async def test_virustotal_missing_key():
    vt = VirusTotalProvider(api_key="")
    result = await vt.lookup("1.1.1.1", "ipv4")
    assert result.status == "missing_key"
    assert result.detections == 0

@pytest.mark.asyncio
async def test_virustotal_success_mocked():
    vt = VirusTotalProvider(api_key="mock_key_vt")
    
    mock_payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 12,
                    "suspicious": 1,
                    "harmless": 50,
                    "undetected": 5
                },
                "reputation": -35,
                "tags": ["phishing", "c2"],
                "last_analysis_results": {
                    "VendorA": {"category": "malicious", "result": "trojan"},
                    "VendorB": {"category": "harmless", "result": "clean"}
                }
            }
        }
    }
    
    mock_response = httpx.Response(200, json=mock_payload, request=httpx.Request("GET", "https://mock.com"))
    
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        result = await vt.lookup("evil.com", "domain")
        
    assert result.status == "success"
    assert result.detections == 12
    assert result.total_engines == 68
    assert result.is_malicious is True
    assert "phishing" in result.attributes["tags"]

@pytest.mark.asyncio
async def test_virustotal_rate_limit_mocked():
    vt = VirusTotalProvider(api_key="mock_key_vt")
    mock_response = httpx.Response(429, text="Quota exceeded", request=httpx.Request("GET", "https://mock.com"))
    
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        result = await vt.lookup("8.8.8.8", "ipv4")
        
    assert result.status == "rate_limited"
    assert "rate limit" in result.summary.lower()

@pytest.mark.asyncio
async def test_alienvault_otx_success_mocked():
    otx = AlienVaultOTXProvider(api_key="mock_key_otx")
    
    mock_payload = {
        "pulse_info": {
            "count": 3,
            "pulses": [
                {
                    "id": "pulse_1",
                    "name": "Campaign Cobalt",
                    "author_name": "AlienVault",
                    "created": "2026-01-01T00:00:00",
                    "malware_families": [{"display_name": "CobaltStrike"}],
                    "adversary": "APT28",
                    "tags": ["rat", "c2"]
                }
            ]
        }
    }
    
    mock_response = httpx.Response(200, json=mock_payload, request=httpx.Request("GET", "https://mock.com"))
    
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        result = await otx.lookup("198.51.100.1", "ipv4")
        
    assert result.status == "success"
    assert result.detections == 3
    assert "CobaltStrike" in result.attributes["malware_families"]
    assert "APT28" in result.attributes["adversaries"]
