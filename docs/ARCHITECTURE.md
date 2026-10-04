# API Sentinel — Architecture & System Design

## 1. High-Level Architecture Overview

API Sentinel is engineered as a modular, asynchronous, defensive security monitoring platform:

```
                    ┌─────────────────────────┐
                    │  API Sentinel Frontend  │
                    │  Next.js 14 + React 18  │
                    │  Tailwind + Recharts    │
                    └───────────┬─────────────┘
                                │ REST / JWT
                                ▼
                    ┌─────────────────────────┐
                    │      FastAPI Core       │
                    │  Gateway & Controllers  │
                    └───────────┬─────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌──────────────┐        ┌──────────────┐        ┌──────────────┐
│  Auth & RBAC │        │ API Discovery│        │ Alert Engine │
│  JWT / Audit │        │ OpenAPI Spec │        │ Dedup/Webhook│
└──────────────┘        └───────┬──────┘        └──────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │  Async Task Queue Pool  │
                    │  (Asyncio Background)   │
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │  Modular Scanner Engine │
                    │  10 Defensive Plugins   │
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │   PostgreSQL / SQLite   │
                    │  Normalized Data Store  │
                    └─────────────────────────┘
```

---

## 2. Component Breakdown

### A. Modular Scanner Framework
Every vulnerability check implements `BaseScanner` (`app/scanners/base.py`):
- `HeaderScanner`: Assesses HSTS, CSP, X-Content-Type-Options, Cache-Control, and Server headers.
- `CORScanner`: Detects wildcard origins and credentialed reflection attacks.
- `TLSScanner`: Evaluates HTTPS enforcement and plaintext HTTP downgrade behaviors.
- `RateLimitScanner`: Validates rate-limiting headers and throttling controls under burst probing.
- `InfoDisclosureScanner`: Inspects responses for stack traces, debug banners, and internal file paths.
- `OpenAPIScanner`: Detects shadow endpoints and specification drift.
- `AuthenticationScanner`: Evaluates authentication enforcement on sensitive endpoints.
- `AuthorizationScanner`: Tests for BOLA/IDOR risk indicators across object identifiers.
- `InputValidationScanner`: Probes boundary parameter validation.
- `SecurityPolicyScanner`: Tests for HTTP TRACE/TRACK method activation and caching policies.

### B. SSRF Protection Engine
Outbound requests undergo strict DNS resolution and IP categorization (`app/core/ssrf.py`). Private networks (RFC 1918), loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), and cloud metadata IMDS IPs are strictly forbidden unless running in explicit local development test mode.

### C. Continuous Monitoring & Anomaly Detection
The telemetry service captures time-series response latency and status codes. The anomaly engine maintains a 24-hour moving baseline and triggers alerts whenever response time exceeds $2.5\sigma$ deviation or error rate spikes above 40%.
