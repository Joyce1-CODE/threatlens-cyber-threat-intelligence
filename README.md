# ThreatLens AI — Cyber Threat Intelligence Platform

[![Python](https://img.shields.io/badge/Python-3.14-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19.0-61DAFB.svg)](https://react.dev/)
[![Material UI](https://img.shields.io/badge/MUI-v6-007FFF.svg)](https://mui.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**ThreatLens AI** is a portfolio-grade, passive cyber threat intelligence platform engineered for cybersecurity analysts and SOC engineers. It provides automated triage, correlation, and evidence-backed risk scoring for Indicators of Compromise (IOCs) across **VirusTotal v3** and **AlienVault OTX (Open Threat Exchange)**.

---

## 🛡️ Key Features & Capabilities

- **Passive IOC Investigation**: Query IP addresses, domains, URLs, and file hashes without interacting with target systems, executing binaries, or performing active network scans.
- **Supported Indicator Types**:
  - **IPv4 & IPv6 Addresses**: Defanging support (`1[.]1[.]1[.]1`, `2001[:]db8[...]`).
  - **Domains**: Fully qualified domain validation and auto-stripping of URL prefixes.
  - **URLs**: Complete URL parsing and validation with defanged scheme normalization (`hxxps://`).
  - **Cryptographic Hashes**: Hexadecimal verification for **MD5** (32 hex), **SHA-1** (40 hex), and **SHA-256** (64 hex).
- **Dual Threat Intelligence Feeds**:
  - **VirusTotal v3 API**: Multi-engine antivirus detection statistics, reputation scores, and top flagged engines.
  - **AlienVault OTX API**: Community threat exchange pulses, known malware family signatures, and threat actor/adversary attributions.
- **Deterministic Risk Scoring Engine**:
  - Transparent 0–100 risk score and standard severity classification (**Low**, **Medium**, **High**, **Critical**).
  - Explicit factor breakdown showing independent engine weights (60% VirusTotal / 40% AlienVault OTX) plus a **Cross-Platform Synergy Bonus (+10 pts)** when both independent providers confirm malicious telemetry.
  - Absence of data is never treated as evidence of safety.
- **Actionable Mitigation Guidance**: Automatically generates defensive countermeasures (firewall blocks, DNS sinkholes, SWG filtering, EDR hash bans) tailored to the indicator type and risk tier.
- **Persistent Investigation History**: SQLite and SQLAlchemy persistence with full pagination, search, and filtering by severity and IOC type.
- **SOC Dark Interface**: Immersive near-black/deep navy dark mode (`#080c14`), glowing cyber accents (`#00f2fe`), interactive Recharts analytics, and responsive navigation.
- **Zero Fabricated Data Guarantee**: In setup mode (no API keys configured), the application displays clear configuration guidance rather than fake mock security statistics.

---

## 🏛️ Architecture Overview

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
│   │   │   └── history_service.py # SQLite history queries, search, pagination, and stats
│   │   ├── routers/
│   │   │   ├── health.py          # /api/health and /api/providers/status
│   │   │   ├── investigate.py     # POST /api/investigate, GET /api/investigations
│   │   │   └── stats.py           # GET /api/dashboard/stats
│   │   └── main.py                # FastAPI app, CORS middleware, exception handlers
│   ├── tests/                     # 19 automated pytest test cases
│   ├── requirements.txt
│   ├── run.py                     # Backend runner with smart port selection
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── api/client.js          # Axios API client with /api proxying
│   │   ├── theme.js               # Material UI dark cybersecurity theme
│   │   ├── components/            # Layout, Common, and Investigation components
│   │   ├── pages/                 # Dashboard, Investigate, History, Detail, Settings
│   │   ├── App.jsx                # React Router v6
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
├── README.md
├── .env.example
└── .gitignore
```

---

## 🚀 Getting Started (macOS Setup)

### Prerequisites
- **Python 3.10+** (Tested on Python 3.14)
- **Node.js v18+** & **npm**

### 1. Clone & Set Up Environment

```bash
cd /Users/chaitanya/ANITIGRAVITY/cyber

# Copy environment template
cp .env.example .env
```

### 2. Configure Threat Intelligence API Keys (Optional)

Open `.env` in your text editor:

```bash
# VirusTotal v3 API Key (Get free key at: https://www.virustotal.com/gui/join-us)
VIRUSTOTAL_API_KEY=""

# AlienVault OTX API Key (Get free key at: https://otx.alienvault.com)
OTX_API_KEY=""
```

> **Note**: Both API keys are optional. If left blank, ThreatLens AI operates in **Setup Mode**, cleanly explaining how to configure keys while allowing you to explore the dashboard, sample IOCs, and history.

---

### 3. Backend Setup & Startup

```bash
# Activate existing virtual environment
source venv/bin/activate

# Or create a new virtual environment if needed:
# python3 -m venv venv && source venv/bin/activate
# pip install -r backend/requirements.txt

# Run the backend service (starts on port 8000 or fallback 8001)
python backend/run.py
```

Backend API will be accessible at: `http://127.0.0.1:8001` (or `http://127.0.0.1:8000`).
Interactive Swagger docs: `http://127.0.0.1:8001/docs`.

---

### 4. Frontend Setup & Startup

Open a second terminal window:

```bash
cd /Users/chaitanya/ANITIGRAVITY/cyber/frontend

# Install dependencies (if not already installed)
npm install

# Start Vite development server
npm run dev
```

The frontend will start at: `http://localhost:5176` (or `http://localhost:5173`).

---

## 🧪 Automated Testing

The backend includes 19 comprehensive unit and integration tests covering:
- IOC validation, regex rules, defanging normalization (`[.]` -> `.`, `hxxp` -> `http`).
- Deterministic risk scoring rules, severity tiers, and multi-source synergy boost.
- Missing credentials graceful handling.
- Mocked HTTP requests testing VirusTotal & AlienVault responses, rate limits (HTTP 429), and 404 cleanly.
- Database persistence, history retrieval, pagination, and dashboard statistics.

To run tests:

```bash
PYTHONPATH=backend ./venv/bin/pytest backend/tests -v
```

All 19 tests pass:
```
backend/tests/test_api.py::test_health_check_endpoint PASSED
backend/tests/test_api.py::test_provider_status_endpoint PASSED
backend/tests/test_api.py::test_investigate_ioc_validation_error PASSED
backend/tests/test_api.py::test_investigate_valid_ioc_and_persistence PASSED
backend/tests/test_ioc_validator.py::test_defanging_normalization PASSED
backend/tests/test_ioc_validator.py::test_ipv4_validation PASSED
backend/tests/test_ioc_validator.py::test_ipv6_validation PASSED
backend/tests/test_ioc_validator.py::test_domain_validation PASSED
backend/tests/test_ioc_validator.py::test_url_validation PASSED
backend/tests/test_ioc_validator.py::test_hashes_validation PASSED
backend/tests/test_ioc_validator.py::test_empty_or_whitespace_input PASSED
backend/tests/test_providers.py::test_virustotal_missing_key PASSED
backend/tests/test_providers.py::test_virustotal_success_mocked PASSED
backend/tests/test_providers.py::test_virustotal_rate_limit_mocked PASSED
backend/tests/test_providers.py::test_alienvault_otx_success_mocked PASSED
backend/tests/test_risk_engine.py::test_risk_scoring_no_providers_configured PASSED
backend/tests/test_risk_engine.py::test_risk_scoring_clean_reputation PASSED
backend/tests/test_risk_engine.py::test_risk_scoring_critical_malicious_with_synergy PASSED
backend/tests/test_risk_engine.py::test_missing_data_does_not_count_as_clean PASSED
======================== 19 passed in 0.47s ========================
```

---

## 📡 API Endpoint Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Service health status and timestamp |
| `GET` | `/api/providers/status` | Configuration status and quotas for VT & OTX (no secrets exposed) |
| `GET` | `/api/dashboard/stats` | Aggregated dashboard metrics, severity counts, and recent scans |
| `POST` | `/api/investigate` | Submit IOC for validation, live correlation, scoring, and persistence |
| `GET` | `/api/investigations` | Paginated investigation history with query search and filters |
| `GET` | `/api/investigations/{id}` | Retrieve full details of an archived investigation |
| `DELETE` | `/api/investigations/{id}` | Remove an investigation record from history |

---

## ⚖️ Deterministic Risk Scoring Formula

ThreatLens AI calculates a consolidated risk score on a scale of 0 to 100:

$$	ext{Score} = \min\left(100, (	ext{Score}_{	ext{VT}} 	imes 0.60) + (	ext{Score}_{	ext{OTX}} 	imes 0.40) + 	ext{Synergy}ight)$$

- **VirusTotal Factor (0–100)**: Evaluates vendor engine consensus (0: Clean, 1: 25 pts, 2: 40 pts, 3–5: 65 pts, 6–14: 85 pts, 15+: 100 pts).
- **AlienVault OTX Factor (0–100)**: Evaluates community threat exchange pulse volume (0: Clean, 1: 35 pts, 2–4: 65 pts, 5+: 85 pts), plus bonuses for identified malware families (+15 pts) and named adversaries (+10 pts).
- **Synergy Bonus (+10 pts)**: Applied when both independent threat intelligence feeds independently confirm malicious activity.
- **Severity Tiers**:
  - `0 – 19`: **Low** (Benign, clean, or unobserved)
  - `20 – 49`: **Medium** (Suspicious indicators, low prevalence)
  - `50 – 74`: **High** (Confirmed threats, multiple vendor detections)
  - `75 – 100`: **Critical** (Active malware campaign or broad industry consensus)

---

## 🔒 Security & Operational Principles

1. **Passive Lookups Only**: The platform never executes payloads, contacts target IP addresses, or initiates active port scanning.
2. **Backend Secret Isolation**: API keys remain strictly on the Python server; they are never passed to the browser or stored in client-side state.
3. **CORS Hardening**: Strict CORS configuration restricted to authorized local frontend origins.
4. **Input Sanitization**: Server-side normalization preventing SQL injection, path traversal, and SSRF attacks.
5. **Zero Fabricated Data**: If an indicator is not found or credentials are missing, this is explicitly communicated rather than generating pseudo-data.

---

## 🗺️ Roadmap & Phase 2 Features

- [ ] Automated ReportLab PDF threat report export.
- [ ] MITRE ATT&CK matrix technique mapping.
- [ ] Bulk IOC investigation via CSV upload.
- [ ] Optional local LLM-assisted threat actor attribution summaries.
