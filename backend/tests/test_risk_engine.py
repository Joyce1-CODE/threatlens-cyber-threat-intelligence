import pytest
from app.providers.base import ProviderResult
from app.services.risk_engine import RiskScoringEngine

def test_risk_scoring_no_providers_configured():
    vt_unconf = ProviderResult(
        provider_name="VirusTotal v3",
        status="missing_key",
        summary="Key not configured"
    )
    otx_unconf = ProviderResult(
        provider_name="AlienVault OTX",
        status="missing_key",
        summary="Key not configured"
    )

    result = RiskScoringEngine.calculate_risk(
        indicator="1.1.1.1",
        indicator_type="ipv4",
        vt_result=vt_unconf,
        otx_result=otx_unconf
    )

    assert result["risk_score"] == 0
    assert result["severity"] == "Unknown"
    assert result["confidence"] == "None"
    assert "Unverified" in result["data_coverage"]

def test_risk_scoring_clean_reputation():
    vt_clean = ProviderResult(
        provider_name="VirusTotal v3",
        status="clean",
        is_malicious=False,
        detections=0,
        total_engines=70
    )
    otx_clean = ProviderResult(
        provider_name="AlienVault OTX",
        status="clean",
        is_malicious=False,
        detections=0
    )

    result = RiskScoringEngine.calculate_risk(
        indicator="8.8.8.8",
        indicator_type="ipv4",
        vt_result=vt_clean,
        otx_result=otx_clean
    )

    assert result["risk_score"] == 0
    assert result["severity"] == "Low"
    assert result["confidence"] == "High"
    assert len(result["evidence"]) >= 2

def test_risk_scoring_critical_malicious_with_synergy():
    vt_malicious = ProviderResult(
        provider_name="VirusTotal v3",
        status="success",
        is_malicious=True,
        detections=18,
        total_engines=72
    )
    otx_malicious = ProviderResult(
        provider_name="AlienVault OTX",
        status="success",
        is_malicious=True,
        detections=6,
        attributes={"malware_families": ["RedLine Stealer"], "adversaries": ["APT29"]}
    )

    result = RiskScoringEngine.calculate_risk(
        indicator="malicious-c2.xyz",
        indicator_type="domain",
        vt_result=vt_malicious,
        otx_result=otx_malicious
    )

    assert result["risk_score"] >= 85
    assert result["severity"] == "Critical"
    assert result["confidence"] == "High"
    assert result["factor_breakdown"]["synergy_boost"] == 10.0
    assert any("Cross-Platform Intelligence Corroboration" in e["title"] for e in result["evidence"])
    assert len(result["recommendations"]) > 0

def test_missing_data_does_not_count_as_clean():
    # If VT returned clean but OTX is missing_key, data coverage must be partial
    vt_clean = ProviderResult(
        provider_name="VirusTotal v3",
        status="clean",
        detections=0,
        total_engines=65
    )
    otx_missing = ProviderResult(
        provider_name="AlienVault OTX",
        status="missing_key"
    )

    result = RiskScoringEngine.calculate_risk(
        indicator="example.com",
        indicator_type="domain",
        vt_result=vt_clean,
        otx_result=otx_missing
    )

    assert result["confidence"] == "Medium"
    assert "Partial" in result["data_coverage"]
