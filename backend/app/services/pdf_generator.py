import io
import re
from datetime import datetime, timezone
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
    HRFlowable,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

from app.models import Investigation

# Brand Colors (Hex & ReportLab colors)
CYAN_MAIN = colors.HexColor("#008080")       # Dark cyan for high contrast print
CYAN_ACCENT = colors.HexColor("#0ea5e9")     # Blue accent
DARK_NAVY = colors.HexColor("#0f172a")       # Slate navy for headings
TEXT_DARK = colors.HexColor("#1e293b")       # Text primary
TEXT_MUTED = colors.HexColor("#64748b")      # Text secondary
BORDER_COLOR = colors.HexColor("#cbd5e1")    # Subtle line border
BG_LIGHT = colors.HexColor("#f8fafc")        # Background fill for tables
BG_CARD = colors.HexColor("#f1f5f9")         # Slightly darker fill

# Severity Colors
SEV_LOW = colors.HexColor("#059669")
SEV_MED = colors.HexColor("#d97706")
SEV_HIGH = colors.HexColor("#ea580c")
SEV_CRIT = colors.HexColor("#dc2626")

class NumberedCanvas(canvas.Canvas):
    """Custom canvas that computes total page count dynamically for Page X of Y footers."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(TEXT_MUTED)
        
        # Header (Top of page)
        self.drawString(36, 756, "THREATLENS AI")
        self.setFont("Helvetica", 8)
        self.drawString(108, 756, "|   CYBER THREAT INTELLIGENCE ASSESSMENT")
        self.drawRightString(576, 756, "CONFIDENTIAL / SOC DEFENSIVE USE")
        
        # Header divider line
        self.setStrokeColor(BORDER_COLOR)
        self.setLineWidth(0.75)
        self.line(36, 748, 576, 748)
        
        # Footer divider line
        self.line(36, 45, 576, 45)
        
        # Footer (Bottom of page)
        self.setFont("Helvetica", 8)
        self.drawString(36, 32, "ThreatLens AI Automated Threat Assessment — Generated from Passive Telemetry")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(576, 32, page_str)
        
        self.restoreState()

def get_severity_color(severity: str):
    s = (severity or "Low").capitalize()
    if s == "Critical":
        return SEV_CRIT
    elif s == "High":
        return SEV_HIGH
    elif s == "Medium":
        return SEV_MED
    return SEV_LOW

def generate_threat_report_pdf(investigation: Investigation) -> bytes:
    """
    Generates a professional, print-ready PDF threat intelligence assessment report.
    Guarantees no overflowing strings, structured layout, and transparent evidence documentation.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Custom Typography Styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=DARK_NAVY,
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=TEXT_MUTED,
        spaceAfter=12,
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=DARK_NAVY,
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=TEXT_DARK,
    )
    mono_style = ParagraphStyle(
        "ReportMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8.5,
        leading=12,
        textColor=DARK_NAVY,
    )
    bold_style = ParagraphStyle(
        "ReportBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=13,
        textColor=DARK_NAVY,
    )
    disclaimer_style = ParagraphStyle(
        "ReportDisclaimer",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=7.5,
        leading=11,
        textColor=TEXT_MUTED,
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("THREAT INTELLIGENCE ASSESSMENT REPORT", title_style))
    created_str = investigation.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if investigation.created_at else "N/A"
    story.append(Paragraph(
        f"<b>Investigation Reference ID:</b> {investigation.id} &nbsp;&nbsp;|&nbsp;&nbsp; <b>Timestamp:</b> {created_str}",
        subtitle_style
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=CYAN_ACCENT, spaceBefore=0, spaceAfter=12))

    # 2. Executive Indicator & Risk Score Summary Box
    sev_color = get_severity_color(investigation.severity)
    
    # Left Column: Target Indicator Details
    indicator_cell = [
        Paragraph("<b>TARGET INDICATOR DETAILS</b>", bold_style),
        Spacer(1, 4),
        Paragraph(f"<b>Normalized Indicator:</b> <font face='Courier'>{investigation.normalized_indicator}</font>", body_style),
        Paragraph(f"<b>Original Submission:</b> <font face='Courier'>{investigation.indicator}</font>", body_style),
        Paragraph(f"<b>Indicator Type:</b> {investigation.indicator_type.upper()}", body_style),
        Paragraph(f"<b>Data Coverage:</b> {investigation.data_coverage}", body_style),
        Paragraph(f"<b>Assessment Confidence:</b> {investigation.confidence}", body_style),
    ]

    # Right Column: Risk Score Callout
    score_cell = [
        Paragraph("<b>THREATLENS RISK ASSESSMENT</b>", bold_style),
        Spacer(1, 4),
        Paragraph(f"<font size='22' color='{sev_color.hexval()}'><b>{investigation.risk_score}</b></font><font size='10' color='#64748b'> / 100</font>", body_style),
        Paragraph(f"<font size='12' color='{sev_color.hexval()}'><b>{investigation.severity.upper()} SEVERITY</b></font>", body_style),
        Spacer(1, 4),
        Paragraph("Deterministic Multi-Feed Heuristic", disclaimer_style),
    ]

    summary_table = Table([[indicator_cell, score_cell]], colWidths=[360, 180])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BG_LIGHT),
        ("BOX", (0, 0), (-1, -1), 1, BORDER_COLOR),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 10))

    # 3. Executive Verdict Callout
    verdict_table = Table([[
        Paragraph(f"<b>EXECUTIVE VERDICT:</b> {investigation.verdict_summary}", body_style)
    ]], colWidths=[540])
    verdict_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BG_CARD),
        ("BOX", (0, 0), (-1, -1), 1, BORDER_COLOR),
        ("LINELEFT", (0, 0), (0, 0), 4, sev_color),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 14))

    # 4. Intelligence Provider Findings Table
    story.append(Paragraph("1. Primary Intelligence Provider Findings", section_heading))
    
    vt_res = (investigation.provider_results or {}).get("virustotal", {})
    otx_res = (investigation.provider_results or {}).get("alienvault_otx", {})
    
    # VirusTotal Details
    vt_status_text = vt_res.get("status", investigation.vt_status).upper()
    vt_dets = investigation.vt_detections
    vt_total = investigation.vt_total_engines
    vt_ratio = f"{vt_dets} / {vt_total} engines" if vt_total > 0 else f"{vt_dets} detections"
    vt_summary = vt_res.get("summary", "No summary recorded.")

    # AlienVault Details
    otx_status_text = otx_res.get("status", investigation.otx_status).upper()
    otx_pulses = investigation.otx_pulse_count
    otx_summary = otx_res.get("summary", "No threat pulses reported.")
    otx_attrs = otx_res.get("attributes", {})
    malware_fams = ", ".join(otx_attrs.get("malware_families", [])) or "None identified"
    adversaries = ", ".join(otx_attrs.get("adversaries", [])) or "Unattributed"

    provider_rows = [
        [
            Paragraph("<b>Provider Name</b>", bold_style),
            Paragraph("<b>Query Status</b>", bold_style),
            Paragraph("<b>Detections / Pulses</b>", bold_style),
            Paragraph("<b>Key Intelligence Findings</b>", bold_style),
        ],
        [
            Paragraph("<b>VirusTotal v3</b><br/><font color='#64748b' size='7.5'>Multi-Engine AV</font>", body_style),
            Paragraph(vt_status_text, bold_style),
            Paragraph(f"<b>{vt_ratio}</b>", body_style),
            Paragraph(f"{vt_summary}", body_style),
        ],
        [
            Paragraph("<b>AlienVault OTX</b><br/><font color='#64748b' size='7.5'>Community Pulses</font>", body_style),
            Paragraph(otx_status_text, bold_style),
            Paragraph(f"<b>{otx_pulses} pulse(s)</b>", body_style),
            Paragraph(f"{otx_summary}<br/><b>Malware:</b> {malware_fams}<br/><b>Adversary:</b> {adversaries}", body_style),
        ]
    ]

    provider_table = Table(provider_rows, colWidths=[110, 85, 115, 230])
    provider_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BG_CARD),
        ("BOX", (0, 0), (-1, -1), 0.75, BORDER_COLOR),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(provider_table)
    story.append(Spacer(1, 14))

    # 5. Risk Scoring Factor Breakdown
    story.append(Paragraph("2. Heuristic Risk Scoring Mathematical Breakdown", section_heading))
    fb = investigation.factor_breakdown or {}
    vt_w = fb.get("virustotal_weight", 0.6)
    vt_s = fb.get("virustotal_score", 0)
    otx_w = fb.get("alienvault_weight", 0.4)
    otx_s = fb.get("alienvault_score", 0)
    syn = fb.get("synergy_boost", 0)
    fin = fb.get("final_score", investigation.risk_score)

    scoring_rows = [
        [Paragraph("<b>Evaluation Factor</b>", bold_style), Paragraph("<b>Raw Score</b>", bold_style), Paragraph("<b>Weight</b>", bold_style), Paragraph("<b>Contribution</b>", bold_style)],
        [Paragraph("VirusTotal Antivirus Consensus", body_style), Paragraph(str(vt_s), body_style), Paragraph(f"{int(vt_w*100)}%", body_style), Paragraph(f"+{round(vt_s * vt_w, 1)} pts", body_style)],
        [Paragraph("AlienVault OTX Community Pulses", body_style), Paragraph(str(otx_s), body_style), Paragraph(f"{int(otx_w*100)}%", body_style), Paragraph(f"+{round(otx_s * otx_w, 1)} pts", body_style)],
        [Paragraph("Cross-Platform Validation Synergy", body_style), Paragraph("Bonus", body_style), Paragraph("N/A", body_style), Paragraph(f"+{round(syn, 1)} pts", body_style)],
        [Paragraph("<b>Consolidated Risk Score (0–100)</b>", bold_style), Paragraph("", body_style), Paragraph("", body_style), Paragraph(f"<b>{fin} / 100</b>", bold_style)],
    ]
    scoring_table = Table(scoring_rows, colWidths=[200, 100, 100, 140])
    scoring_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BG_CARD),
        ("BACKGROUND", (0, -1), (-1, -1), BG_LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.75, BORDER_COLOR),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(scoring_table)
    story.append(Spacer(1, 14))

    # 6. Corroborating Evidence Signals Table
    evidence_list = investigation.evidence or []
    if evidence_list:
        story.append(Paragraph(f"3. Supporting Evidence Signals ({len(evidence_list)} items)", section_heading))
        ev_rows = [[Paragraph("<b>Source</b>", bold_style), Paragraph("<b>Signal Title</b>", bold_style), Paragraph("<b>Detailed Observation</b>", bold_style)]]
        for ev in evidence_list[:8]: # Up to top 8 evidence signals
            src = ev.get("source", "Telemetry")
            title = ev.get("title", "")
            desc = ev.get("description", "")
            ev_rows.append([
                Paragraph(src, body_style),
                Paragraph(f"<b>{title}</b>", body_style),
                Paragraph(desc, body_style),
            ])
        ev_table = Table(ev_rows, colWidths=[110, 160, 270])
        ev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BG_CARD),
            ("BOX", (0, 0), (-1, -1), 0.75, BORDER_COLOR),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(ev_table)
        story.append(Spacer(1, 14))

    # 7. Actionable Mitigation Guidance
    recs = investigation.recommendations or []
    if recs:
        story.append(Paragraph("4. Defensive Mitigation Guidance", section_heading))
        rec_items = []
        for r in recs:
            rec_items.append([Paragraph("•", bold_style), Paragraph(r, body_style)])
        rec_table = Table(rec_items, colWidths=[15, 525])
        rec_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 2),
            ("RIGHTPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(rec_table)
        story.append(Spacer(1, 14))

    # 8. Disclaimer and Methodology Notes (Keep Together to avoid awkward breaks)
    disclaimer_block = [
        Paragraph("<b>ASSESSMENT METHODOLOGY & LEGAL DISCLAIMER:</b>", disclaimer_style),
        Spacer(1, 3),
        Paragraph(
            "This Threat Intelligence Assessment is an automated, passive heuristic evaluation synthesized from external threat feeds "
            "(VirusTotal v3 and AlienVault OTX). ThreatLens AI operates in a passive telemetry capacity only and does not perform active network scanning, "
            "binary payload execution, or interactive perimeter probing. A risk score of 0 does not constitute a guarantee of safety, as zero-day attacks "
            "and recently minted infrastructure may lack historical detections. Conversely, isolated detections may reflect low-confidence false positives. "
            "Defensive teams should cross-reference findings with internal endpoint detection (EDR), SIEM logs, and network telemetry before implementing "
            "service-disruptive containment procedures.",
            disclaimer_style
        )
    ]
    story.append(KeepTogether(disclaimer_block))

    # Build PDF with multi-page NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()
