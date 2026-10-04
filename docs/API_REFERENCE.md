# API Sentinel — REST API Reference (v1)

Base URL: `http://localhost:8000/api/v1`

All responses follow the standard JSON envelope structure:
```json
{
  "success": true,
  "data": {},
  "meta": {}
}
```

---

## Endpoints Summary

### Authentication (`/auth`)
- `POST /auth/register` — Register new user account.
- `POST /auth/login` — Authenticate and receive JWT access + refresh tokens.
- `POST /auth/refresh` — Rotate refresh token and obtain new access token.
- `GET /auth/me` — Retrieve authenticated user profile and permissions.
- `GET /auth/sessions` — List active user sessions.
- `POST /auth/sessions/{id}/revoke` — Revoke a session.

### API Management (`/apis`)
- `GET /apis` — List registered APIs (supports filtering by `environment`, `risk`, `monitoring`, `search`).
- `POST /apis` — Register new authorized API target.
- `GET /apis/{id}` — Retrieve detailed API record with endpoints, credentials, and vulnerability stats.
- `DELETE /apis/{id}` — Delete API target and associated scans/findings.
- `POST /apis/import-openapi` — Parse and import OpenAPI 3.x / Swagger 2.0 specification.

### Scans (`/scans`)
- `POST /scans?api_id={id}` — Trigger asynchronous vulnerability scan (`QUICK`, `STANDARD`, `DEEP`, `CUSTOM`).
- `GET /scans` — List scan execution history.
- `GET /scans/{id}` — Get scan details, telemetry counters, and discovered findings.

### Vulnerabilities (`/vulnerabilities`)
- `GET /vulnerabilities` — List security findings across all APIs or filtered by API, severity, or status.
- `GET /vulnerabilities/{id}` — Deep vulnerability investigation detail with redacted evidence.
- `PUT /vulnerabilities/{id}` — Update triage status, assignee, or due date.
- `POST /vulnerabilities/{id}/comments` — Add investigation comment.

### Continuous Monitoring (`/monitoring`)
- `GET /monitoring/overview` — Aggregated uptime % and latency metrics across APIs.
- `GET /monitoring/apis/{id}` — 24-hour time series response time metrics for an API.
- `POST /monitoring/apis/{id}/check` — Execute immediate on-demand health check.
- `GET /monitoring/anomalies` — List statistically detected latency and error rate anomalies.

### Alerts (`/alerts`)
- `GET /alerts` — List security threat alerts.
- `PUT /alerts/{id}` — Acknowledge or resolve an alert.
- `GET /alerts/channels` — List notification webhook channels.
- `POST /alerts/channels` — Register new outbound webhook channel.

### Reports (`/reports`)
- `POST /reports/generate` — Generate executive or compliance report (`HTML`, `JSON`, `CSV`).
- `GET /reports` — List generated reports.
- `GET /reports/{id}/download` — Download report raw payload.

### Audit Logs (`/audit-logs`)
- `GET /audit-logs` — Query immutable security audit log timeline.

### SOC Dashboard (`/dashboard`)
- `GET /dashboard/stats` — Aggregated SOC statistics, severity distributions, and trend lines.
