# API Sentinel — Secure API Vulnerability Monitoring & Security Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-green.svg)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Next.js-14.2%2B-black.svg)](https://nextjs.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-3.4%2B-38bdf8.svg)](https://tailwindcss.com/)

**API Sentinel** is an enterprise-grade, defensive API Security, Vulnerability Monitoring, and Continuous Analytics platform. It continuously evaluates authorized API targets for security weaknesses, configuration flaws, anomalous response latencies, and specification drift, providing security analysts, DevSecOps teams, and SOC engineers with full visibility over their API attack surface.

---

## 🌟 Key Capabilities

- **Defensive Modular Scanner Engine**: 10 dedicated scanner plugins (`HeaderScanner`, `CORScanner`, `TLSScanner`, `RateLimitScanner`, `InfoDisclosureScanner`, `OpenAPIScanner`, `AuthenticationScanner`, `AuthorizationScanner`, `InputValidationScanner`, `SecurityPolicyScanner`).
- **Strict SSRF Protection**: Comprehensive outbound URL validation blocking loopbacks, RFC 1918 private subnets, link-local, and cloud IMDS endpoints (`169.254.169.254`).
- **Encrypted Credential Storage**: AES-GCM / Fernet encryption at rest with automated masking in UI views, evidence traces, and logs.
- **Continuous Monitoring & Anomaly Detection**: Scheduled health checks, 24h response time percentiles, uptime %, and 2.5-sigma statistical anomaly alerting.
- **OWASP API Security Top 10 Mapping**: Real-time compliance cross-referencing (API1:2023 BOLA, API2:2023 Broken Auth, API8:2023 Misconfig, etc.).
- **Executive & Compliance Reporting**: Instant generation of PDF-ready HTML, structured JSON, and raw CSV security reports.
- **Enterprise RBAC**: Role-based access control (`SUPER_ADMIN`, `SECURITY_ADMIN`, `SECURITY_ANALYST`, `DEVELOPER`, `VIEWER`).
- **Bundled Demo Vulnerable API**: Self-contained, safe local testbed (`http://localhost:8001`) for immediate hands-on verification.

---

## 🚀 Quick Start (Local Development)

### 1. Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### 2. Launch Everything (Windows)
Double-click `start_dev.bat` or run:
```bash
# Windows Command Prompt
start_dev.bat
```

### 3. Manual Step-by-Step Launch

**Start Backend:**
```bash
cd backend
pip install -r requirements.txt
python -m app.seed
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

**Start Demo API Target:**
```bash
cd demo-api
pip install -r requirements.txt
python app.py
```

**Start Next.js Frontend:**
```bash
cd frontend
npm install
npm run dev
```

Visit **http://localhost:3000** to open the SOC Cyber Defense Dashboard.

---

## 🔑 Default Demonstration Accounts

| Role | Email | Password |
|---|---|---|
| **Super Admin** | `admin@sentinel.sec` | `SentinelAdmin2026!` |
| **Security Analyst** | `analyst@sentinel.sec` | `AnalystPass2026!` |
| **Developer** | `dev@sentinel.sec` | `DevPass2026!` |

---

## 🐳 Docker Deployment

To launch the full containerized stack (PostgreSQL, Redis, FastAPI Backend, Next.js Web Client, Demo API, and Nginx Reverse Proxy):

```bash
docker compose up --build -d
```

- Web Client: `http://localhost`
- Backend API Documentation: `http://localhost/docs`
- Demo API: `http://localhost:8001/docs`

---

## 🧪 Running Tests

Execute the automated backend test suite:
```bash
cd backend
pytest -v
```

---

## 📂 Project Structure

```
api-sentinel/
├── backend/                  # FastAPI Core Backend & Scanners
│   ├── app/
│   │   ├── api/              # REST Endpoints (v1)
│   │   ├── core/             # SSRF, RBAC, Security, Crypto, Database
│   │   ├── models/           # SQLAlchemy Data Models
│   │   ├── scanners/         # 10 Defensive Scanner Plugins
│   │   ├── services/         # Scoring, Monitoring, Alerts, Reports
│   │   ├── main.py           # FastAPI Entrypoint & Lifespan
│   │   └── seed.py           # Seed Demo Data Script
│   ├── tests/                # Pytest Test Suite
│   └── requirements.txt
├── demo-api/                 # Isolated Vulnerable Test API
│   ├── app.py
│   └── requirements.txt
├── frontend/                 # Next.js 14 SOC Web Application
│   ├── src/
│   │   ├── app/              # App Router Pages
│   │   ├── components/       # Layout, Navigation, Charts
│   │   └── lib/              # API Client & TypeScript Types
│   └── package.json
├── infrastructure/           # Nginx & Docker configs
├── docs/                     # Architecture, Security & API docs
├── docker-compose.yml        # Multi-container orchestration
└── start_dev.bat             # One-click Windows launch
```
