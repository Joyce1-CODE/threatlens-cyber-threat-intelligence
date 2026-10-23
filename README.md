# ThreatLens AI — Cyber Threat Intelligence & Investigation Platform

[![Python](https://img.shields.io/badge/Python-3.14-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19.0-61DAFB.svg)](https://react.dev/)
[![Material UI](https://img.shields.io/badge/MUI-v6-007FFF.svg)](https://mui.com/)
[![ReportLab](https://img.shields.io/badge/ReportLab-5.1+-red.svg)](https://www.reportlab.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**ThreatLens AI** is an enterprise-grade, passive cyber threat intelligence and Indicator of Compromise (IOC) investigation platform built for SOC analysts, incident responders, and cybersecurity engineering teams. It correlates security telemetry across **VirusTotal v3** and **AlienVault OTX**, computes transparent heuristic risk scores, generates executive PDF threat reports, enforces provider rate limiting, and supports role-based access control (RBAC).

---

## 🎯 Problem Statement & Objectives

Modern SOC teams and incident responders face alert fatigue and fragmented threat data. Investigating suspicious IP addresses, domains, URLs, and file hashes across separate browser tabs is slow, error-prone, and burns API rate limits. Furthermore, querying threat indicators manually risks accidental active interaction with malicious adversary infrastructure.

**ThreatLens AI** solves this by providing:
1. **Strictly Passive Telemetry**: Queries third-party threat intelligence databases without contacting target hosts, executing malware payloads, or crawling adversary URLs.
2. **Unified Intelligence Correlation**: Aggregates antivirus consensus, threat actor attribution, and malware family intelligence into a single pane of glass.
3. **Deterministic & Explainable Scoring**: Replaces opaque AI "black-box" scores with an explainable 0–100 mathematical risk engine.
4. **Actionable Deliverables**: Generates multi-page executive PDF threat reports with containment countermeasures and processes batches of up to 50 IOCs via rate-bounded CSV triage.
5. **Enterprise Security & Reliability**: Features in-memory TTL caching, token-bucket rate limiting, exponential backoff retries, and JWT-based Role-Based Access Control (RBAC).

---

## 🛡️ Core Features & Capabilities

### 1. Passive Multi-Type IOC Investigation
- **Indicator Validation & Defanging**: Automatic defanging normalization (`1[.]1[.]1[.]1`, `hxxps://`, `evil[.]com`) and syntax validation.
- **Supported Formats**:
  - **IPv4 & IPv6**: Public address verification and reverse ASN lookup.
  - **Domains**: RFC-compliant hostname validation with protocol stripping.
  - **URLs**: Scheme, host, and path validation with URL-safe base64 encoding.
  - **File Hashes**: Hexadecimal validation for **MD5** (32 hex), **SHA-1** (40 hex), and **SHA-256** (64 hex).

### 2. Live Threat Intelligence Feeds
- **VirusTotal v3 REST API**:
  - 90+ antivirus security vendor engine detection verdicts (CrowdStrike, Microsoft, Kaspersky, Sophos).
  - Multi-engine detection ratio, reputation score, and threat classification tags.
  - Autonomous System (AS) owner, CIDR network range, and country attribution.
- **AlienVault OTX (Open Threat Exchange) v1 API**:
  - Community threat pulses, campaign sightings, and adversary attribution (e.g. APT28, Lazarus Group).
  - Association with known malware strains (e.g. CobaltStrike, RedLine Stealer).
- **Setup Mode & Transparency**:
  - If API keys are omitted, the application runs cleanly in **Setup Mode**, providing setup guides without fabricating data.

### 3. Deterministic 0–100 Risk Engine
- **Explainable Mathematics**: 60% VirusTotal antivirus consensus weight + 40% AlienVault OTX pulse intelligence weight.
- **Cross-Platform Synergy Bonus (+10 pts)**: Awarded when independent platforms confirm malicious activity.
- **Data Coverage & Safety Guarantee**: Missing or failed provider queries are flagged as **Unverified / Unknown**, never assumed safe.
- **Severity Tiers**:
  - `Unverified`: No data available (0 providers active/responsive)
  - `0 – 19`: **Low Risk** (Benign, clean, verified by active sources)
  - `20 – 49`: **Medium Risk** (Suspicious indicators, isolated vendor detections)
  - `50 – 74`: **High Risk** (Confirmed threat signatures, corroborated pulse tracking)
  - `75 – 100`: **Critical Risk** (Widespread vendor consensus, active APT/malware campaign)

### 4. Executive PDF Threat Reports (ReportLab)
- **One-Click SOC Dossiers**: Downloadable print-ready PDF reports from `/investigation/:id` and `/investigate`.
- **Report Elements**: Executive summary header, risk score callout, multi-provider findings matrix, mathematical factor breakdown, evidence telemetry, defensive mitigation countermeasures (EDR hash banning, DNS sinkholes, SWG URL filters), and legal disclaimers.
- **Multi-Page Layout**: Dynamic `NumberedCanvas` with running headers, footers, and page numbers (`Page X of Y`).

### 5. Rate-Bounded Bulk CSV Triage
- **Pre-Flight Parsing**: Drag-and-drop CSV or TXT file upload (supports comma, semicolon, tab delimiters). Auto-detects IOC columns, removes duplicates, and identifies syntax errors.
- **Rate-Limit Pacing & Circuit Breaker**:
  - Enforces a 15-second delay between VirusTotal requests when live keys are configured to comply with the free-tier quota (4 requests/minute).
  - Batch-level circuit breaker: if HTTP 429 quota exhaustion occurs, remaining batch items are marked as `vt_status="rate_limited"` without stalling the queue, while AlienVault OTX lookups continue uninterrupted.
- **Export Enriched Results**: Export triaged batches to RFC-4180 compliant CSV files with risk scores, severities, and verdict summaries.

### 6. Role-Based Access Control (RBAC) & Authentication
- **JWT Architecture**: 15-minute access token + 7-day secure HTTP-only refresh token with automatic rotation and replay-attack revocation.
- **Three Tiered Roles**:
  - **Admin**: Full platform access, user account management (`/users`), role assignment, and system configuration.
  - **Senior Analyst**: Full IOC investigation, bulk triage, PDF generation, and history management.
  - **Read-Only Analyst**: Dashboard telemetry, investigation history viewing, and report downloads.
- **Password Security**: Passwords hashed with **bcrypt** (12 work factor salt rounds).

### 7. Reliability & Resiliency Engineering
- **In-Memory TTL Caching**: Thread-safe 10-minute cache (`ProviderCache`) avoids redundant external queries for identical IOCs, conserving API quotas.
- **Exponential Backoff**: Automatic retries for transient 5xx errors and network timeouts.
- **`Retry-After` Header Parsing**: Complies with provider HTTP 429 backoff headers.
- **Secret Redaction**: API keys and tokens are automatically stripped from error logs and response bodies.

---

## 🏛️ Project Architecture

```
threatlens-cyber-threat-intelligence/
├── backend/
│   ├── app/
│   │   ├── config.py              # Pydantic Settings & environment variables
│   │   ├── database.py            # SQLite engine, sessions, and admin bootstrap
│   │   ├── models.py              # SQLAlchemy models (Investigation, User, RefreshToken)
│   │   ├── schemas.py             # Pydantic v2 validation schemas
│   │   ├── ioc_validator.py       # Defanging normalization & syntax validation
│   │   ├── providers/
│   │   │   ├── base.py            # Abstract BaseThreatProvider with retry/backoff & sanitization
│   │   │   ├── cache.py           # In-memory thread-safe TTL cache (10 min)
│   │   │   ├── virustotal.py      # VirusTotal v3 HTTPX client with backoff
│   │   │   └── alienvault_otx.py  # AlienVault OTX v1 HTTPX client with backoff
│   │   ├── services/
│   │   │   ├── risk_engine.py     # Deterministic heuristic scoring & recommendation rules
│   │   │   ├── rate_limiter.py    # ProviderRateLimiter with pacing & circuit breaker
│   │   │   ├── aggregator.py      # Concurrent provider execution with error isolation
│   │   │   ├── history_service.py # SQLite history queries, search, pagination, and stats
│   │   │   ├── pdf_generator.py   # ReportLab multi-page executive PDF report builder
│   │   │   ├── bulk_service.py    # CSV parsing, deduplication, and rate-paced triage
│   │   │   └── auth_service.py    # Bcrypt hashing, JWT issuance, rotation, and RBAC
│   │   ├── routers/
│   │   │   ├── auth.py            # /api/auth/login, /refresh, /logout, /me
│   │   │   ├── users.py           # /api/users CRUD (Admin only)
│   │   │   ├── health.py          # /api/health and /api/providers/status
│   │   │   ├── investigate.py     # POST /api/investigate, GET /api/investigations, report.pdf
│   │   │   ├── stats.py           # GET /api/dashboard/stats
│   │   │   └── bulk.py            # POST /api/bulk/preview, /triage, /export
│   │   └── main.py                # FastAPI application, CORS, and route registration
│   ├── tests/
│   │   ├── conftest.py            # In-memory test fixtures and auth header generators
│   │   ├── test_api.py            # API endpoint health, validation, and persistence
│   │   ├── test_auth.py           # Authentication, JWT rotation, and RBAC tests
│   │   ├── test_ioc_validator.py  # Defanging and IOC syntax validation
│   │   ├── test_providers.py      # Mocked provider response and rate-limit tests
│   │   ├── test_reliability.py    # Retry, backoff, Retry-After, cache, and circuit-breaker tests
│   │   ├── test_risk_engine.py    # Scoring rules, synergy bonus, and safety guarantees
│   │   ├── test_pdf_report.py     # ReportLab PDF report generation tests
│   │   └── test_bulk_triage.py    # CSV upload, preview, triage, and export tests
│   ├── bootstrap_admin.py         # CLI admin account bootstrap utility
│   ├── requirements.txt           # Python dependency manifest
│   ├── run.py                     # Development server launcher (port 8001 / 8000)
│   └── .env.example               # Safe environment configuration template
├── frontend/
│   ├── src/
│   │   ├── api/client.js          # Axios API client with auth interceptors
│   │   ├── contexts/AuthContext.jsx # Authentication state, JWT refresh, and role context
│   │   ├── theme.js               # Material UI dark cybersecurity theme
│   │   ├── components/
│   │   │   ├── Common/            # SeverityBadge, RiskScoreMeter, StatCard, ProtectedRoute
│   │   │   ├── Investigation/     # IOCInputForm, ProviderResultCard, EvidenceTimeline
│   │   │   └── Layout/            # AppLayout, Sidebar, Header
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx      # Overview metrics & threat analytics
│   │   │   ├── Investigate.jsx    # Live IOC investigation console
│   │   │   ├── BulkTriage.jsx     # CSV upload, preview, and batch triage
│   │   │   ├── History.jsx        # Searchable investigation archive
│   │   │   ├── InvestigationDetail.jsx # Forensic investigation detail & PDF export
│   │   │   ├── Users.jsx          # Admin user management console
│   │   │   ├── Settings.jsx       # Threat feed status & telemetry
│   │   │   └── Login.jsx          # Analyst authentication portal
│   │   ├── App.jsx                # React Router v6 route configuration
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
├── .env.example                   # Root safe environment template
├── .gitignore                     # Comprehensive secret and build exclusion rules
├── LICENSE                        # MIT License
└── README.md
```

---

## 💻 Technology Stack

| Domain | Technologies |
|---|---|
| **Backend** | Python 3.14, FastAPI, SQLAlchemy 2.0, Pydantic v2, HTTPX, ReportLab 5.1, PyJWT, Bcrypt |
| **Database** | SQLite (`threatlens.db`) |
| **Frontend** | React 19, Vite, Material UI (MUI v6), Lucide Icons, Recharts, Axios |
| **Threat APIs** | VirusTotal v3 REST API, AlienVault OTX v1 REST API |
| **Testing** | Pytest, Pytest-Asyncio, HTTPX TestClient |

---

## 🚀 Getting Started

### 1. Prerequisites
- **Python 3.10+** (Tested on Python 3.14)
- **Node.js 18+** & **npm**
- **Git**

### 2. Clone the Repository
```bash
git clone https://github.com/Joyce1-CODE/threatlens-cyber-threat-intelligence.git
cd threatlens-cyber-threat-intelligence
```

### 3. Backend Setup
Create and activate a Python virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate       # On Windows: venv\Scripts\activate
pip install -r backend/requirements.txt
```

Configure your environment file from the template:
```bash
cp .env.example .env
```

Edit `.env` to configure your settings and optional threat feed API keys:
```env
APP_NAME="ThreatLens AI"
APP_ENV="development"
DATABASE_URL="sqlite:///./threatlens.db"

# Optional: Add your free API keys (app operates in Setup Mode if omitted)
VIRUSTOTAL_API_KEY=""
OTX_API_KEY=""

# External request timeout
REQUEST_TIMEOUT_SECONDS=12.0

# Authentication & JWT Configuration
JWT_SECRET_KEY="generate_a_secure_random_key_here"
JWT_ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# Initial Bootstrap Administrator (Auto-created on first start)
ADMIN_INITIAL_USERNAME="admin"
ADMIN_INITIAL_EMAIL="admin@threatlens.ai"
ADMIN_INITIAL_PASSWORD="Admin@ChangeMe123!"
```

> **Security Note**: Never commit `.env` to version control. The `.env` file is excluded via `.gitignore`. Users must register for their own free API keys on [VirusTotal](https://www.virustotal.com/gui/join-us) and [AlienVault OTX](https://otx.alienvault.com).

Start the backend server:
```bash
PYTHONPATH=backend python backend/run.py
```
- API Server: `http://127.0.0.1:8001`
- Interactive OpenAPI Docs: `http://127.0.0.1:8001/docs`

### 4. Frontend Setup
In a new terminal window:
```bash
cd frontend
npm install
npm run dev -- --host 0.0.0.0
```
- Web Application: `http://localhost:5176`

Log in using the bootstrap administrator credentials configured in your `.env` (default: `admin` / `Admin@ChangeMe123!`), or the account created during initial setup.

---

## 📡 API Endpoint Reference

| Method | Endpoint | Access Role | Description |
|---|---|---|---|
| `POST` | `/api/auth/login` | Public | Authenticate analyst & receive JWT + HTTP-only refresh cookie |
| `POST` | `/api/auth/refresh` | Public | Rotate refresh token & issue new access token |
| `POST` | `/api/auth/logout` | Authenticated | Revoke refresh token & clear authentication cookies |
| `GET` | `/api/auth/me` | Authenticated | Retrieve current user profile and role |
| `GET` | `/api/users` | Admin | List all registered analyst accounts |
| `POST` | `/api/users` | Admin | Create a new analyst account with specific role |
| `PATCH` | `/api/users/{id}` | Admin | Update user details, role, or active status |
| `GET` | `/api/health` | Public | System health check and UTC timestamp |
| `GET` | `/api/providers/status` | Authenticated | Threat intelligence provider configuration status |
| `GET` | `/api/dashboard/stats` | Authenticated | SOC KPI statistics, severity distributions, and telemetry |
| `POST` | `/api/investigate` | Senior / Admin | Perform live IOC investigation with scoring & persistence |
| `GET` | `/api/investigations` | Authenticated | Searchable, paginated investigation history |
| `GET` | `/api/investigations/{id}` | Authenticated | Retrieve full forensic record of an investigation |
| `GET` | `/api/investigations/{id}/report.pdf` | Authenticated | **Download executive PDF threat intelligence report** |
| `DELETE` | `/api/investigations/{id}` | Senior / Admin | Delete an archived investigation |
| `POST` | `/api/bulk/preview` | Senior / Admin | **Pre-flight parse and validate uploaded CSV indicators** |
| `POST` | `/api/bulk/triage` | Senior / Admin | **Execute rate-paced batch triage (max 50 IOCs)** |
| `POST` | `/api/bulk/export` | Senior / Admin | **Export triage results to RFC-4180 CSV** |

---

## 🧪 Automated Testing

The automated test suite contains **55 tests** across 8 test modules:

```bash
PYTHONPATH=backend pytest backend/tests -v
```

### Test Coverage Overview:
- **`test_auth.py`** (15 tests): Password hashing, login authentication, deactivated user rejection, token expiration, refresh token rotation, replay attack prevention, logout revocation, route protection, role permissions (Admin, Senior Analyst, Read-Only), privilege escalation prevention, and safe administrator bootstrap.
- **`test_api.py`** (4 tests): Health check, provider status masking, input validation errors, and investigation persistence.
- **`test_ioc_validator.py`** (7 tests): Defanging parser, IPv4, IPv6, domain, URL, MD5, SHA-1, SHA-256 validation, and whitespace sanitization.
- **`test_providers.py`** (4 tests): Missing credentials, mocked VirusTotal 200 payload, HTTP 429 handling, and AlienVault OTX pulse parsing.
- **`test_reliability.py`** (10 tests):
  - VirusTotal 401/403 permanent error short-circuiting (zero retries)
  - `Retry-After` header parsing and bounded backoff
  - Transient 503 error with automatic retry recovery
  - Connection timeout retry exhaustion handling
  - In-memory TTL caching verification (zero redundant HTTP calls)
  - AlienVault OTX 401/403 error short-circuiting
  - AlienVault OTX transient 500 retry recovery
  - Token-bucket rate limiter pacing and circuit breaker activation
  - Bulk triage graceful handling of 429 quota exhaustion without failing batch
  - Automatic API key redaction in error sanitization
- **`test_risk_engine.py`** (4 tests): Unconfigured zero-state, clean reputation, critical malicious consensus with synergy bonus, and missing-data safety guarantee.
- **`test_pdf_report.py`** (4 tests): ReportLab PDF byte generation, unconfigured data PDF handling, endpoint success with attachment headers, and 404 handling.
- **`test_bulk_triage.py`** (7 tests): Valid CSV preview, duplicates/syntax error handling, empty CSV rejection, file upload validation, non-CSV rejection, batch triage execution and persistence, and CSV export.

**Result: 55 Passed (100% pass rate)**

---

## 🏗️ Building for Production

Build the frontend static assets:
```bash
cd frontend
npm run build
```
Vite generates optimized production assets in `frontend/dist/`.

---

## 🚀 Production Deployment (Vercel + Render + PostgreSQL)

ThreatLens AI is architected for zero-cost, high-reliability deployment using free-tier cloud infrastructure:
- **Frontend**: Hosted on **Vercel** (Global Edge CDN, Automatic HTTPS, SPA Routing via `vercel.json`).
- **Backend**: Hosted on **Render** (FastAPI ASGI Web Service on Python 3.11/3.14 via `render.yaml`).
- **Database**: **Managed PostgreSQL** on Render, [Neon](https://neon.tech), or [Supabase](https://supabase.com) (providing persistent investigation history across container restarts).

```mermaid
graph LR
    User[SOC Analyst Browser] -->|HTTPS| Vercel[Vercel Global CDN<br/>React + Vite SPA]
    Vercel -->|REST API / CORS| Render[Render Web Service<br/>FastAPI Backend]
    Render -->|SQLAlchemy 2.0 Pool| DB[(Managed PostgreSQL<br/>Render / Neon / Supabase)]
    Render -->|Passive Lookups| VT[VirusTotal v3 API]
    Render -->|Passive Lookups| OTX[AlienVault OTX API]
```

### 1. Database Persistence Evaluation (Critical)
> [!WARNING]
> **SQLite on Render is Ephemeral:** Render's free-tier Web Services run on ephemeral disks. If you run SQLite in production on Render, your database resets whenever the service goes to sleep (after 15 minutes of inactivity) or redeploys.
> **Solution:** Use a free managed PostgreSQL database. SQLAlchemy connects seamlessly to PostgreSQL out of the box with `psycopg2-binary`.

#### Connecting to Managed PostgreSQL:
1. Create a free PostgreSQL database on [Render](https://render.com), [Neon](https://neon.tech), or [Supabase](https://supabase.com).
2. Copy the connection string (e.g. `postgresql://user:password@ep-host.region.neon.tech/threatlens?sslmode=require`).
3. Set `DATABASE_URL` in your Render Environment Variables. ThreatLens automatically normalizes `postgres://` to `postgresql://` and configures connection pooling (`pool_pre_ping=True`).

#### Migrating Existing Local SQLite Data:
To transfer existing local investigation history and user accounts to PostgreSQL:
```bash
python backend/migrate_to_postgres.py --source threatlens.db --target "postgresql://user:pass@host:5432/threatlens"
```
*Your local SQLite file remains 100% intact and untouched.*

---

### 2. Backend Deployment on Render

#### Option A: 1-Click Render Blueprint (Recommended)
1. Push your repository to GitHub.
2. In the [Render Dashboard](https://dashboard.render.com), click **New +** > **Blueprint**.
3. Select your repository: `https://github.com/Joyce1-CODE/threatlens-cyber-threat-intelligence`.
4. Render automatically detects [`render.yaml`](render.yaml) and provisions:
   - `threatlens-api` Web Service
   - `threatlens-db` Managed PostgreSQL instance
   - Auto-generated 256-bit `JWT_SECRET_KEY`
5. Fill in the required environment variables:
   - `CORS_ORIGINS`: Set to your Vercel URL (e.g. `https://threatlens.vercel.app`)
   - `VIRUSTOTAL_API_KEY`: Your VirusTotal API key (optional)
   - `OTX_API_KEY`: Your AlienVault OTX key (optional)
6. Click **Apply**.

#### Option B: Manual Web Service Setup on Render
1. In Render, click **New +** > **Web Service**.
2. Connect your GitHub repository.
3. Configure the settings:
   - **Name**: `threatlens-api`
   - **Root Directory**: `backend`
   - **Environment**: `Python`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - **Health Check Path**: `/api/health`
4. Add Environment Variables:
   | Variable | Value / Description |
   | :--- | :--- |
   | `APP_ENV` | `production` |
   | `PYTHON_VERSION` | `3.11.9` |
   | `DATABASE_URL` | `postgresql://...` (or leave default for ephemeral SQLite demo) |
   | `JWT_SECRET_KEY` | Strong random string (generate with `openssl rand -hex 32`) |
   | `COOKIE_SECURE` | `true` |
   | `COOKIE_SAMESITE` | `none` |
   | `CORS_ORIGINS` | `https://your-frontend.vercel.app` |
   | `VIRUSTOTAL_API_KEY` | Your VirusTotal API Key |
   | `OTX_API_KEY` | Your AlienVault OTX Key |
   | `ADMIN_INITIAL_PASSWORD` | Strong initial admin password |

---

### 3. Frontend Deployment on Vercel

1. Log into [Vercel](https://vercel.com) and click **Add New...** > **Project**.
2. Import your GitHub repository: `threatlens-cyber-threat-intelligence`.
3. Configure Project Settings:
   - **Framework Preset**: `Vite`
   - **Root Directory**: Click `Edit` and select `frontend` (or leave as root; both contain [`vercel.json`](vercel.json) configurations).
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
4. Configure Environment Variables:
   - `VITE_API_URL`: Set to your Render backend URL (e.g. `https://threatlens-api.onrender.com/api`).
5. Click **Deploy**.

> [!TIP]
> **Single-Page Application (SPA) Routing:** Both root [`vercel.json`](vercel.json) and [`frontend/vercel.json`](frontend/vercel.json) include automatic rewrite rules that route all paths `/(.*)` to `/index.html`. Direct browser refreshes on `/investigate`, `/history`, `/bulk`, `/settings`, and `/users` load seamlessly without HTTP 404 errors.

---

### 4. Cross-Origin Cookie & Authentication Architecture

When deploying the frontend on `vercel.app` and the backend on `onrender.com`:
1. **Primary Security**: Refresh tokens are issued as `HttpOnly`, `Secure`, `SameSite=None` cookies over HTTPS.
2. **Resilient Fallback**: Modern browsers with strict third-party cookie restrictions (Safari ITP) are automatically supported via ThreatLens's session-scoped refresh fallback mechanism, guaranteeing that session rotation never drops unexpectedly.
3. **In-Memory Access Tokens**: Short-lived access tokens (15-minute expiration) are strictly held in JavaScript application memory and never written to `localStorage`, eliminating XSS token theft vectors.

---

## 🔒 Security & Privacy Guarantees

1. **Zero Target Contact**: ThreatLens AI never interacts with target IPs, domains, or URLs. All queries are strictly passive lookups against third-party threat intelligence databases.
2. **Backend Credential Isolation**: API keys, JWT secret keys, and database credentials remain exclusively on the Python backend. No credentials are leaked to frontend bundles or Git.
3. **Safe Git Hygiene**: Real `.env` files, SQLite databases, and virtual environments are strictly ignored via `.gitignore`.
4. **Rate-Limit Compliance**: The platform respects VirusTotal public free-tier limits (4 requests/minute) using automated request pacing.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
