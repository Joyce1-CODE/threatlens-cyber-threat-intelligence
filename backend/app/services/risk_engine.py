from typing import Dict, Any, List, Tuple
from app.providers.base import ProviderResult

class RiskScoringEngine:
    """
    ThreatLens AI Deterministic Risk Scoring Engine.
    
    Principles:
    1. Deterministic and transparent: Every point is accounted for in factor_breakdown.
    2. Missing data is never treated as evidence of safety.
    3. Multi-source synergy: Corroboration across independent intelligence platforms
       yields a validated cross-correlation bonus.
    4. Heuristic labeling: Explicitly marked as ThreatLens AI heuristic assessment.
    
    Severity Tiers:
    - 0  to 19: Low (Benign, clean, or unobserved)
    - 20 to 49: Medium (Suspicious indicators, low-volume sightings)
    - 50 to 74: High (Confirmed threat signatures, multiple vendor detections)
    - 75 to 100: Critical (Widespread vendor consensus, active APT/malware campaign)
    """

    @classmethod
    def calculate_risk(
        cls,
        indicator: str,
        indicator_type: str,
        vt_result: ProviderResult,
        otx_result: ProviderResult
    ) -> Dict[str, Any]:
        evidence: List[Dict[str, Any]] = []
        recommendations: List[str] = []
        
        # 1. Determine Provider Availability
        vt_active = vt_result.status in ("success", "clean", "not_found")
        otx_active = otx_result.status in ("success", "clean", "not_found")
        
        # Track data coverage
        if vt_active and otx_active:
            data_coverage = "Comprehensive (2/2 Sources)"
            confidence = "High"
        elif vt_active:
            data_coverage = "Partial (VirusTotal v3 only)"
            confidence = "Medium"
        elif otx_active:
            data_coverage = "Partial (AlienVault OTX only)"
            confidence = "Medium"
        else:
            data_coverage = "Unverified (0 Sources Configured/Available)"
            confidence = "None"

        # 2. Score VirusTotal Factor (0 - 100)
        vt_score = 0.0
        vt_detections = vt_result.detections
        vt_total = vt_result.total_engines
        
        if vt_active:
            if vt_detections == 0:
                vt_score = 0.0
                if vt_result.status == "clean" and vt_total > 0:
                    evidence.append({
                        "source": "VirusTotal v3",
                        "severity": "low",
                        "title": "Clean Vendor Consensus",
                        "description": f"0 of {vt_total} security engines flagged this indicator as malicious."
                    })
                elif vt_result.status == "not_found":
                    evidence.append({
                        "source": "VirusTotal v3",
                        "severity": "info",
                        "title": "No Historical Sightings",
                        "description": "Indicator not present in VirusTotal scan archives. Note: Absence of record is not proof of safety."
                    })
            elif vt_detections == 1:
                vt_score = 25.0
                evidence.append({
                    "source": "VirusTotal v3",
                    "severity": "medium",
                    "title": "Isolated Engine Detection (1 engine)",
                    "description": "Single engine flagged indicator. Potential low-prevalence threat or isolated false positive."
                })
            elif vt_detections == 2:
                vt_score = 40.0
                evidence.append({
                    "source": "VirusTotal v3",
                    "severity": "medium",
                    "title": "Suspicious Activity (2 engines)",
                    "description": "2 security engines reported malicious classification."
                })
            elif 3 <= vt_detections <= 5:
                vt_score = 65.0
                evidence.append({
                    "source": "VirusTotal v3",
                    "severity": "high",
                    "title": f"Elevated Threat Consensus ({vt_detections} engines)",
                    "description": f"{vt_detections} independent vendors confirmed malicious categorization."
                })
            elif 6 <= vt_detections <= 14:
                vt_score = 85.0
                evidence.append({
                    "source": "VirusTotal v3",
                    "severity": "critical",
                    "title": f"Broad Vendor Consensus ({vt_detections} engines)",
                    "description": f"{vt_detections} security vendors flagged this IOC as malicious/phishing/malware."
                })
            else: # 15+
                vt_score = 100.0
                evidence.append({
                    "source": "VirusTotal v3",
                    "severity": "critical",
                    "title": f"Severe Malicious Consensus ({vt_detections} engines)",
                    "description": f"Overwhelming confirmation: {vt_detections} vendors flagged this active threat."
                })
        else:
            evidence.append({
                "source": "VirusTotal v3",
                "severity": "info",
                "title": "Provider Unavailable",
                "description": vt_result.summary or "VirusTotal was not queried (unconfigured or request error)."
            })

        # 3. Score AlienVault OTX Factor (0 - 100)
        otx_score = 0.0
        otx_pulse_count = vt_result_attr = otx_result.detections # pulse count
        otx_attrs = otx_result.attributes
        malware_families = otx_attrs.get("malware_families", [])
        adversaries = otx_attrs.get("adversaries", [])
        
        if otx_active:
            if otx_pulse_count == 0:
                otx_score = 0.0
                evidence.append({
                    "source": "AlienVault OTX",
                    "severity": "low" if otx_result.status == "clean" else "info",
                    "title": "No Threat Pulses Reported",
                    "description": "Indicator does not appear in AlienVault community threat exchange pulses."
                })
            elif otx_pulse_count == 1:
                otx_score = 35.0
                evidence.append({
                    "source": "AlienVault OTX",
                    "severity": "medium",
                    "title": "Single Threat Pulse Sighting",
                    "description": "Indicator appears in 1 community threat intelligence pulse."
                })
            elif 2 <= otx_pulse_count <= 4:
                otx_score = 65.0
                evidence.append({
                    "source": "AlienVault OTX",
                    "severity": "high",
                    "title": f"Corroborated Threat Pulses ({otx_pulse_count} pulses)",
                    "description": f"Observed across {otx_pulse_count} distinct threat exchange pulses."
                })
            else: # 5+
                otx_score = 85.0
                evidence.append({
                    "source": "AlienVault OTX",
                    "severity": "critical",
                    "title": f"High Threat Pulse Prevalence ({otx_pulse_count} pulses)",
                    "description": f"Widely tracked indicator referenced across {otx_pulse_count} threat campaigns."
                })
                
            # OTX Bonus: Known Malware Families
            if malware_families:
                otx_score = min(100.0, otx_score + 15.0)
                family_str = ", ".join(malware_families[:3])
                evidence.append({
                    "source": "AlienVault OTX",
                    "severity": "critical",
                    "title": f"Associated Malware Families: {family_str}",
                    "description": f"Indicator is directly linked to known malware signatures ({family_str})."
                })
                
            # OTX Bonus: Named Threat Actor / Adversary
            if adversaries:
                otx_score = min(100.0, otx_score + 10.0)
                adv_str = ", ".join(adversaries[:2])
                evidence.append({
                    "source": "AlienVault OTX",
                    "severity": "critical",
                    "title": f"Attributed Threat Actor: {adv_str}",
                    "description": f"Pulse intelligence links indicator to known threat group: {adv_str}."
                })
        else:
            evidence.append({
                "source": "AlienVault OTX",
                "severity": "info",
                "title": "Provider Unavailable",
                "description": otx_result.summary or "AlienVault OTX was not queried (unconfigured or request error)."
            })

        # 4. Synthesize Combined Risk Score
        synergy_boost = 0.0
        
        if vt_active and otx_active:
            # Weighted average: 60% VT vendor engines, 40% OTX pulse intelligence
            vt_weight = 0.60
            otx_weight = 0.40
            base_score = (vt_score * vt_weight) + (otx_score * otx_weight)
            
            # Synergy bonus if BOTH independent providers observed malicious threat signals
            if vt_score >= 25.0 and otx_score >= 35.0:
                synergy_boost = 10.0
                evidence.append({
                    "source": "ThreatLens AI Correlation Engine",
                    "severity": "critical",
                    "title": "Cross-Platform Intelligence Corroboration",
                    "description": "Both VirusTotal vendor engines and AlienVault OTX community pulses independently confirm malicious activity (+10 validation boost)."
                })
            final_calculated = min(100.0, base_score + synergy_boost)
        elif vt_active:
            vt_weight = 1.0
            otx_weight = 0.0
            final_calculated = vt_score
        elif otx_active:
            vt_weight = 0.0
            otx_weight = 1.0
            final_calculated = otx_score
        else:
            vt_weight = 0.0
            otx_weight = 0.0
            final_calculated = 0.0

        risk_score = int(round(final_calculated))
        
        # 5. Classify Severity
        if risk_score >= 75:
            severity = "Critical"
        elif risk_score >= 50:
            severity = "High"
        elif risk_score >= 20:
            severity = "Medium"
        else:
            severity = "Low"

        # 6. Generate Actionable Mitigation Recommendations
        recommendations = cls._generate_recommendations(indicator_type, severity, risk_score, malware_families)

        # 7. Formulate Verdict Summary
        if not (vt_active or otx_active):
            verdict_summary = (
                "No threat intelligence providers are configured or responsive. "
                "Configure your VirusTotal and/or AlienVault OTX API keys in .env to perform live threat evaluations."
            )
        elif severity == "Critical":
            verdict_summary = (
                f"Critical threat detected ({risk_score}/100). Strong multi-source confirmation indicates active "
                "hostile infrastructure or malware payload. Immediate containment is strongly advised."
            )
        elif severity == "High":
            verdict_summary = (
                f"High risk indicator ({risk_score}/100). Corroborated malicious detections suggest confirmed hostile "
                "activity. Restrict access and investigate endpoint logs."
            )
        elif severity == "Medium":
            verdict_summary = (
                f"Suspicious indicator ({risk_score}/100). Low-to-moderate threat indicators detected. "
                "Monitor network telemetry and verify internal traffic patterns."
            )
        else:
            if confidence in ("High", "Medium"):
                verdict_summary = (
                    f"Low risk ({risk_score}/100). No malicious indicators were reported across available threat sources. "
                    "Maintain standard perimeter logging and monitoring."
                )
            else:
                verdict_summary = "Unverified indicator (0/100). No threat intelligence data available to establish risk."

        factor_breakdown = {
            "virustotal_weight": vt_weight,
            "virustotal_score": round(vt_score, 1),
            "alienvault_weight": otx_weight,
            "alienvault_score": round(otx_score, 1),
            "synergy_boost": round(synergy_boost, 1),
            "final_score": risk_score
        }

        return {
            "risk_score": risk_score,
            "severity": severity,
            "confidence": confidence,
            "data_coverage": data_coverage,
            "verdict_summary": verdict_summary,
            "evidence": evidence,
            "factor_breakdown": factor_breakdown,
            "recommendations": recommendations
        }

    @classmethod
    def _generate_recommendations(
        cls,
        ioc_type: str,
        severity: str,
        risk_score: int,
        malware_families: List[str]
    ) -> List[str]:
        recs: List[str] = []
        
        if severity in ("Critical", "High"):
            if ioc_type in ("ipv4", "ipv6"):
                recs.append("Immediately block inbound and outbound traffic to this IP on perimeter firewalls and Cloudflare/WAF.")
                recs.append("Query SIEM/NetFlow logs for internal hosts that initiated connections to this IP within the past 30 days.")
                recs.append("Isolate any endpoints exhibiting continuous beaconing or large data egress to this IP.")
            elif ioc_type == "domain":
                recs.append("Apply a DNS sinkhole or null-route entry for this domain on enterprise resolvers (e.g. Pi-hole, Infoblox).")
                recs.append("Inspect web proxy and SSL/TLS interception logs for user requests to this domain or associated subdomains.")
                recs.append("Check DNS query telemetry for historical resolution spikes across workstation fleets.")
            elif ioc_type == "url":
                recs.append("Block the full URL path on secure web gateways (SWG) and web content filters.")
                recs.append("Scan corporate email gateways to quarantine phishing lures containing this link.")
                recs.append("Reset credentials for any users who submitted authentication data to this URL.")
            elif ioc_type in ("md5", "sha1", "sha256"):
                recs.append("Create an enterprise-wide EDR hash-block rule across all managed endpoints (Defender, CrowdStrike, SentinelOne).")
                recs.append("Hunt for file creation events, execution artifacts, and scheduled tasks associated with this hash.")
                recs.append("Isolate and quarantine any systems where this binary was executed; submit file to sandbox for dynamic behavioral analysis.")

            if malware_families:
                family = malware_families[0]
                recs.append(f"Deploy specific threat eradication runbooks for the identified '{family}' malware strain.")
        elif severity == "Medium":
            recs.append("Place this indicator on watchlist status in your SIEM or XDR detection rule set.")
            recs.append("Review recent firewall and proxy access logs for abnormal or recurring communication.")
            recs.append("Verify if this entity corresponds to internal services, CDNs, or legitimate partner infrastructure.")
        else:
            recs.append("Standard monitoring: Retain normal logging without imposing automated blocking.")
            recs.append("If this indicator was flagged in an alert, re-examine neighboring IOCs (such as redirected domains or parent processes).")

        return recs
