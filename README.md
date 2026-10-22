# ThreatLens AI — Cyber Threat Intelligence Platform

[![Python](https://img.shields.io/badge/Python-3.14-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19.0-61DAFB.svg)](https://react.dev/)
[![Material UI](https://img.shields.io/badge/MUI-v6-007FFF.svg)](https://mui.com/)
[![ReportLab](https://img.shields.io/badge/ReportLab-5.1+-red.svg)](https://www.reportlab.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**ThreatLens AI** is an enterprise-grade, passive cyber threat intelligence and IOC triage platform built for security analysts, incident responders, and SOC teams. It correlates indicators of compromise across **VirusTotal v3** and **AlienVault OTX**, computes transparent heuristic risk scores, generates executive PDF threat reports, and performs rate-bounded bulk CSV triage.

---

## 🛡️ Core Capabilities & Advanced Features

### 1. Passive Threat Intelligence Investigation
- **Strictly Passive Telemetry**: Queries third-party threat intelligence databases without contacting target IP addresses, executing malware binaries, or crawling remote URLs.
- **Full Indicator Support**:
  - **IPv4 & IPv6**: Address validation and defanging normalization (`1[.]1[.]1[.]1`, `2001[:]db8[...]`).
  - **Domains**: RFC-compliant validation with automatic URL-prefix removal (`evil[.]com`).
  - **URLs**: Scheme, host, and path validation with defanged protocol normalization (`hxxps://`).
  - **File Hashes**: Hexadecimal validation for **MD5** (32 hex), **SHA-1** (40 hex), and **SHA-256** (64 hex).

### 2. Multi-Source Threat Intelligence Feeds
- **VirusTotal v3 REST API**:
  - Multi-engine antivirus detection statistics (e.g. 14 / 72 engines flagged).
  - Reputation scores and threat classification tags.
  - Granular breakdown of top security vendor engine verdicts (CrowdStrike, Kaspersky, Microsoft, Sophos).
- **AlienVault OTX (Open Threat Exchange) v1 API**:
  - Community threat exchange pulse sightings and campaign tracking.
  - Direct association with known malware families (e.g. CobaltStrike, RedLine Stealer).
  - Attribution to named threat groups and adversaries (e.g. APT28, Lazarus Group).

### 3. Deterministic Risk Scoring Engine
- **Transparent 0–100 Score**: Every point is explicitly accounted for in the factor breakdown.
- **Dual-Source Consensus Weights**: 60% VirusTotal antivirus consensus + 40% AlienVault OTX pulse intelligence.
- **Cross-Platform Synergy Bonus (+10 pts)**: Applied when both independent threat intelligence feeds independently confirm malicious activity.
- **Absence of Data Safety Rule**: Missing records or unconfigured feeds are flagged as unobserved; they are **never** treated as proof of safety.
- **Severity Tiers**:
  - `0 – 19`: **Low Risk** (Benign, clean, or unobserved)
  - `20 – 49`: **Medium Risk** (Suspicious signals, isolated detections)
  - `50 – 74`: **High Risk** (Confirmed threat signatures, multiple vendor detections)
  - `75 – 100`: **Critical Risk** (Widespread vendor consensus or active malware campaign)

### 4. Executive PDF Threat Reports (ReportLab)
- **One-Click Downloadable Intelligence Dossiers** from `/investigation/:id` and `/investigate`.
- **Report Content**:
  - Professional SOC executive header, reference UUID, and UTC timestamp.
  - Target indicator metadata and normalized format.
  - Prominent risk score callout and severity badge.
  - Multi-provider findings comparison matrix.
  - Mathematical factor scoring breakdown table.
  - Supporting evidence signals list.
  - Actionable defensive countermeasures (EDR hash banning, DNS sinkholes, SWG URL filtering).
  - Assessment methodology and legal liability disclaimers.
- **Multi-Page Layout**: Dynamic `NumberedCanvas` with running headers, footers, and page numbers (`Page X of Y`).

### 5. Bulk IOC Triage & CSV Analysis
- **Dedicated Route**: `/bulk` integrated into main navigation.
- **Pre-Flight Parsing & Validation**:
  - Upload CSV or TXT file (supports comma, semicolon, tab delimiters).
  - Auto-detects indicator column (`indicator`, `ioc`, `ip`, `domain`, `hash`, `url`, `target`, `host`, `address`).
  - Allows manual column selection if multiple columns exist.
  - Automatic defanging normalization (`evil[.]com` $\to$ `evil.com`).
  - Pre-flight validation chips: Valid IOCs, Duplicates (auto-skipped), and Syntax Errors with specific error tooltips.
- **Safety & Resource Guardrails**:
  - **Batch Limit**: Max 50 unique indicators per batch.
  - **File Size Limit**: Max 2 MB per CSV upload.
  - **Bounded Concurrency**: Uses an `asyncio.Semaphore(4)` worker pool to respect provider rate limits and avoid connection exhaustion.
  - **Persistence**: Every completed investigation is automatically saved to the SQLite database.
- **Export Enriched Results**: Download comprehensive triage spreadsheet with detection counts, risk scores, severities, and verdicts.

---

## 🏛️ Project Architecture

```
cyber/
├── backend/
│   ├── app/
│   │   ├── config.py              # Pydantic Settings & environment variables
│   │   ├── database.py            # SQLite engine & SQLAlchemy session lifecycle
│   │   ├── models.py              # SQLAlchemy Investigation model
│   │   ├── schemas.py             # Pydantic v2 validation & response models
│   │   ├── ioc_validator.py       # Regex validation, defanging normalization, type detector
│   │   ├── providers/
│   │   │   ├── base.py            # Abstract BaseThreatProvider interface
│   │   │   ├── virustotal.py      # VirusTotal v3 HTTPX async client
│   │   │   └── alienvault_otx.py  # AlienVault OTX v1 HTTPX async client
│   │   ├── services/
│   │   │   ├── risk_engine.py     # Deterministic heuristic scoring & recommendation rules
│   │   │   ├── aggregator.py      # Concurrent provider execution (asyncio.gather)
│   │   │   ├── history_service.py # SQLite history queries, search, pagination, and stats
│   │   │   ├── pdf_generator.py   # ReportLab multi-page executive PDF report builder
│   │   │   └── bulk_service.py    # CSV parser, deduplication, semaphore bounded triage, and export
│   │   ├── routers/
│   │   │   ├── health.py          # /api/health and /api/providers/status
│   │   │   ├── investigate.py     # POST /api/investigate, GET /api/investigations, report.pdf
│   │   │   ├── stats.py           # GET /api/dashboard/stats
│   │   │   └── bulk.py            # POST /api/bulk/preview, /triage, /export
│   │   └── main.py                # FastAPI app, CORS middleware, exception handlers
│   ├── tests/
│   │   ├── test_api.py            # Health, status, investigation, and persistence tests
│   │   ├── test_ioc_validator.py  # Defanging, IP, domain, URL, hash syntax tests
│   │   ├── test_providers.py      # Mocked VT & OTX responses, rate limits (429), missing keys
│   │   ├── test_risk_engine.py    # Scoring rules, synergy bonus, unverified states
│   │   ├── test_pdf_report.py     # PDF generation, headers, 404 handling, missing provider data
│   │   └── test_bulk_triage.py    # CSV upload, preview, validation, batch triage, CSV export
│   ├── requirements.txt
│   ├── run.py                     # Backend runner with smart port selection
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── api/client.js          # Axios API client with PDF & Bulk Triage methods
│   │   ├── theme.js               # Material UI dark cybersecurity theme
│   │   ├── components/
│   │   │   ├── Common/            # SeverityBadge, RiskScoreMeter, StatCard, EmptyState, ProviderStatusBadge
│   │   │   ├── Investigation/     # IOCInputForm, ProviderResultCard, EvidenceTimeline, RecommendationsCard, FactorBreakdown
│   │   │   └── Layout/            # AppLayout, Sidebar, Header
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx      # Overview metrics & Recharts analytics
│   │   │   ├── Investigate.jsx    # Live IOC investigation console & PDF download
│   │   │   ├── BulkTriage.jsx     # CSV upload, preview, batch triage, and export
│   │   │   ├── History.jsx        # Searchable, filterable archive with pagination
│   │   │   ├── InvestigationDetail.jsx # Deep dive record review & PDF download
│   │   │   └── Settings.jsx       # API credentials guide & system telemetry
│   │   ├── App.jsx                # React Router v6
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
├── README.md
├── .env.example
└── .gitignore
```

---

## 🚀 Local Setup & Startup (macOS)

### 1. Prerequisites
- **Python 3.10+** (Tested on Python 3.14)
- **Node.js v18+** & **npm**

### 2. Configure Environment Variables
Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Edit `.env` (API keys are optional; app operates in **Setup Mode** if omitted):
```env
# VirusTotal v3 API Key (https://www.virustotal.com/gui/join-us)
VIRUSTOTAL_API_KEY=""

# AlienVault OTX API Key (https://otx.alienvault.com)
OTX_API_KEY=""

# Request Timeout (seconds)
REQUEST_TIMEOUT_SECONDS=12.0
```

### 3. Start Backend Service
```bash
# Activate virtual environment
source venv/bin/activate

# Install dependencies if needed
pip install -r backend/requirements.txt

# Start backend server (starts on port 8001 or fallback 8000)
python backend/run.py
```
- API Base: `http://127.0.0.1:8001`
- Interactive Swagger UI: `http://127.0.0.1:8001/docs`

### 4. Start Frontend Application
In a separate terminal:
```bash
cd frontend

# Install dependencies if needed
npm install

# Start Vite dev server
npm run dev
```
- Web Application: `http://localhost:5176`

---

## 📡 API Endpoint Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health status and timestamp |
| `GET` | `/api/providers/status` | Provider configuration and quota status (no secrets exposed) |
| `GET` | `/api/dashboard/stats` | Persisted metrics, severity counts, and recent scans |
| `POST` | `/api/investigate` | Investigate single IOC with live scoring and persistence |
| `GET` | `/api/investigations` | Paginated investigation history with query search and filters |
| `GET` | `/api/investigations/{id}` | Retrieve full details of an archived investigation |
| `GET` | `/api/investigations/{id}/report.pdf` | **Download executive PDF threat intelligence report** |
| `DELETE` | `/api/investigations/{id}` | Delete an investigation record from history |
| `POST` | `/api/bulk/preview` | **Preview and validate uploaded CSV indicators** |
| `POST` | `/api/bulk/triage` | **Execute rate-bounded batch triage (max 50 IOCs)** |
| `POST` | `/api/bulk/export` | **Export batch triage results as downloadable CSV** |

---

## 🧪 Automated Testing

The automated test suite comprises **30 tests** across 6 test modules:

```bash
PYTHONPATH=backend ./venv/bin/pytest backend/tests -v
```

### Test Suite Summary:
- **`test_api.py`** (4 tests): Health check, provider status masking, validation errors, investigation persistence and retrieval.
- **`test_ioc_validator.py`** (7 tests): Defanging parser, IPv4, IPv6, domain, URL, MD5, SHA-1, SHA-256 syntax and whitespace handling.
- **`test_providers.py`** (4 tests): Unconfigured providers, mocked VirusTotal 200 payload, HTTP 429 rate limits, and AlienVault OTX pulse parsing.
- **`test_risk_engine.py`** (4 tests): Unconfigured zero-state, clean reputation, critical malicious consensus with synergy bonus, and missing-data safety guarantee.
- **`test_pdf_report.py`** (4 tests): PDF bytes generation, unconfigured data PDF handling, endpoint success with attachment headers, and 404 on nonexistent ID.
- **`test_bulk_triage.py`** (7 tests): Valid CSV preview, duplicates/syntax error handling, empty CSV rejection, file upload endpoint, non-CSV rejection, batch triage execution and persistence, CSV export endpoint.

**Result: 30 Passed in 0.54s (100% passing)**

---

## 📄 Sample CSV Format for Bulk Triage

ThreatLens AI accepts standard CSV files with an indicator column name such as `indicator`, `ioc`, `ip`, `domain`, `hash`, or `url`:

```csv
indicator,source,notes
8.8.8.8,DNS,Google Public DNS
1.1.1.1,DNS,Cloudflare Resolver
evil[.]c2-beacon.ru,Telemetry,Defanged domain
hxxps://phish-secure-portal[.]xyz/login,Email,Phishing lure
44d88612fea8a8f36de82e1278abb02f,File,EICAR Standard Test Hash
```

---

## 🔒 Security & Operational Guarantees

1. **Zero Outbound Target Contact**: ThreatLens AI never interacts directly with investigated hosts, performs port scans, or executes payloads.
2. **Backend Secret Isolation**: API credentials remain strictly on the Python server and are never exposed to the browser or client-side storage.
3. **CORS Restrictions**: Configured specifically for local frontend development origins.
4. **Rate-Limit Respecting Concurrency**: Bulk triage limits parallel queries to 4 concurrent workers to protect external API quotas.
5. **Zero Fabricated Data Guarantee**: In setup mode (no API keys configured) or when an indicator is not found in public archives, the application explicitly shows unverified states rather than fabricated data.
