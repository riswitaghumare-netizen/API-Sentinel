import bcrypt from "bcryptjs";
import {
  User,
  APITarget,
  APIDetail,
  APIEndpoint,
  Scan,
  ScanFinding,
  FindingEvidence,
  FindingComment,
  MonitoringOverview,
  MetricPoint,
  AnomalyEvent,
  AlertItem,
  DashboardStats,
  SecurityReport,
  AuditLog,
} from "./types";

export function generateId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

export interface StoredUser extends User {
  hashed_password: string;
}

// In-Memory Database Store for API Sentinel
class SentinelStore {
  public users: StoredUser[] = [];
  public apis: APIDetail[] = [];
  public scans: Scan[] = [];
  public findings: ScanFinding[] = [];
  public monitoringOverview: MonitoringOverview[] = [];
  public anomalies: AnomalyEvent[] = [];
  public alerts: AlertItem[] = [];
  public reports: SecurityReport[] = [];
  public auditLogs: AuditLog[] = [];
  private initialized = false;

  constructor() {
    this.seed();
  }

  public seed() {
    if (this.initialized) return;
    this.initialized = true;

    const now = new Date().toISOString();
    const twoHoursAgo = new Date(Date.now() - 2 * 3600 * 1000).toISOString();
    const oneDayAgo = new Date(Date.now() - 24 * 3600 * 1000).toISOString();

    // 1. Users
    const adminId = "u-admin-001";
    const analystId = "u-analyst-002";
    const devId = "u-dev-003";

    this.users = [
      {
        id: adminId,
        email: "admin@sentinel.sec",
        hashed_password: bcrypt.hashSync("SentinelAdmin2026!", 10),
        full_name: "Alex Mercer (SecOps Lead)",
        role: "SUPER_ADMIN",
        is_active: true,
        created_at: oneDayAgo,
      },
      {
        id: analystId,
        email: "analyst@sentinel.sec",
        hashed_password: bcrypt.hashSync("AnalystPass2026!", 10),
        full_name: "Elena Rostova (Security Analyst)",
        role: "SECURITY_ANALYST",
        is_active: true,
        created_at: oneDayAgo,
      },
      {
        id: devId,
        email: "dev@sentinel.sec",
        hashed_password: bcrypt.hashSync("DevPass2026!", 10),
        full_name: "David Chen (Lead Backend Dev)",
        role: "DEVELOPER",
        is_active: true,
        created_at: oneDayAgo,
      },
    ];

    // 2. APIs
    const demoApiId = "api-demo-001";
    const authApiId = "api-auth-002";
    const legacyApiId = "api-legacy-003";

    const demoEndpoints: APIEndpoint[] = [
      {
        id: "ep-001",
        path: "/api/v1/users",
        method: "GET",
        summary: "List all users",
        parameters: [],
        request_body_schema: {},
        responses_schema: { "200": { description: "User list" } },
        is_authenticated: false,
        auth_type: "NONE",
        is_deprecated: false,
        tags: ["users", "customers"],
      },
      {
        id: "ep-002",
        path: "/api/v1/users/{user_id}",
        method: "GET",
        summary: "Get user by ID (BOLA Vulnerable)",
        parameters: [{ name: "user_id", in: "path", required: true, type: "integer" }],
        request_body_schema: {},
        responses_schema: { "200": { description: "User object" } },
        is_authenticated: false,
        auth_type: "NONE",
        is_deprecated: false,
        tags: ["users"],
      },
      {
        id: "ep-003",
        path: "/api/v1/orders",
        method: "GET",
        summary: "List orders",
        parameters: [],
        request_body_schema: {},
        responses_schema: { "200": { description: "Orders" } },
        is_authenticated: false,
        auth_type: "NONE",
        is_deprecated: false,
        tags: ["orders"],
      },
      {
        id: "ep-004",
        path: "/api/v1/orders",
        method: "POST",
        summary: "Create order",
        parameters: [],
        request_body_schema: { type: "object", properties: { amount: { type: "number" } } },
        responses_schema: { "201": { description: "Created" } },
        is_authenticated: false,
        auth_type: "NONE",
        is_deprecated: false,
        tags: ["orders"],
      },
      {
        id: "ep-005",
        path: "/api/v1/admin/debug",
        method: "GET",
        summary: "Internal staging debug endpoint (Shadow API)",
        parameters: [],
        request_body_schema: {},
        responses_schema: { "200": { description: "Debug config" } },
        is_authenticated: false,
        auth_type: "NONE",
        is_deprecated: false,
        tags: ["admin", "debug", "shadow"],
      },
    ];

    this.apis = [
      {
        id: demoApiId,
        project_id: "proj-001",
        name: "FinTech Payments API (Demo Lab)",
        description: "Production-representative financial transactions and customer profile API service.",
        base_url: "/api/demo",
        environment: "STAGING",
        owner: "David Chen",
        team: "Payments Engineering",
        tags: ["financial", "payments", "pci-scope", "v2-gateway"],
        technology: "Python / FastAPI / PostgreSQL",
        version: "v2.4.0",
        monitoring_status: "ENABLED",
        risk_classification: "HIGH",
        security_score: 68.5,
        health_status: "HEALTHY",
        endpoints_count: 5,
        open_vulnerabilities_count: 4,
        critical_vulns: 1,
        high_vulns: 2,
        medium_vulns: 1,
        low_vulns: 0,
        info_vulns: 0,
        last_scanned_at: twoHoursAgo,
        last_monitored_at: now,
        created_at: oneDayAgo,
        endpoints: demoEndpoints,
        credentials: [
          {
            id: "cred-001",
            auth_type: "API_KEY",
            key_name: "Staging Service Key",
            header_name: "X-API-Key",
            masked_preview: "sk_live_****9941",
            created_at: oneDayAgo,
          },
        ],
      },
      {
        id: authApiId,
        project_id: "proj-001",
        name: "Customer Identity & Auth Service",
        description: "OAuth 2.0 / OpenID Connect identity provider, session management and MFA.",
        base_url: "https://auth.internal.sentinel.sec",
        environment: "PRODUCTION",
        owner: "Elena Rostova",
        team: "SecOps Core",
        tags: ["identity", "oauth2", "jwt", "zero-trust"],
        technology: "Go / OAuth2 / Redis",
        version: "v3.1.2",
        monitoring_status: "ENABLED",
        risk_classification: "LOW",
        security_score: 94.2,
        health_status: "HEALTHY",
        endpoints_count: 8,
        open_vulnerabilities_count: 1,
        critical_vulns: 0,
        high_vulns: 0,
        medium_vulns: 1,
        low_vulns: 0,
        info_vulns: 0,
        last_scanned_at: twoHoursAgo,
        last_monitored_at: now,
        created_at: oneDayAgo,
        endpoints: [],
        credentials: [],
      },
      {
        id: legacyApiId,
        project_id: "proj-001",
        name: "Legacy Reporting Gateway",
        description: "Quarterly compliance and legacy batch ledger extraction service.",
        base_url: "https://reports-legacy.internal.sentinel.sec",
        environment: "DEVELOPMENT",
        owner: "David Chen",
        team: "Data Ops",
        tags: ["legacy", "batch", "internal-only"],
        technology: "Node.js / Express",
        version: "v1.1.0",
        monitoring_status: "PAUSED",
        risk_classification: "MEDIUM",
        security_score: 79.0,
        health_status: "HEALTHY",
        endpoints_count: 3,
        open_vulnerabilities_count: 2,
        critical_vulns: 0,
        high_vulns: 1,
        medium_vulns: 1,
        low_vulns: 0,
        info_vulns: 0,
        last_scanned_at: oneDayAgo,
        last_monitored_at: oneDayAgo,
        created_at: oneDayAgo,
        endpoints: [],
        credentials: [],
      },
    ];

    // 3. Scan & Findings
    const scanId = "scan-001";
    const finding1Id = "finding-001";
    const finding2Id = "finding-002";
    const finding3Id = "finding-003";
    const finding4Id = "finding-004";

    const findingsList: ScanFinding[] = [
      {
        id: finding1Id,
        scan_id: scanId,
        api_id: demoApiId,
        api_name: "FinTech Payments API (Demo Lab)",
        endpoint_id: "ep-005",
        title: "Unauthenticated Shadow API Endpoint Exposing Internal Staging Secrets",
        severity: "CRITICAL",
        cvss_score: 9.8,
        risk_score: 9.8,
        confidence: "CERTAIN",
        http_method: "GET",
        affected_endpoint_path: "/api/v1/admin/debug",
        description:
          "The endpoint /api/v1/admin/debug responds without any authentication token and discloses database connection credentials, internal routing topology, and staging configuration variables.",
        risk_explanation:
          "Attacker can extract production database passwords, pivot laterally into VPC subnets, and compromise customer transactional data.",
        remediation:
          "Deprecate and unroute /api/v1/admin/debug immediately from external ingress. Require strict mutual TLS and Super Admin role authorization for all diagnostic probes.",
        references: ["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
        owasp_category: "API9:2023 Improper Inventory Management",
        cwe_id: "CWE-200",
        nist_control: "AC-3 / CM-8",
        status: "OPEN",
        scanner_name: "ShadowEndpointDetector",
        assignee_id: analystId,
        assignee_name: "Elena Rostova (Security Analyst)",
        due_date: new Date(Date.now() + 48 * 3600 * 1000).toISOString(),
        first_detected_at: twoHoursAgo,
        last_detected_at: twoHoursAgo,
        created_at: twoHoursAgo,
        evidence: {
          id: "ev-001",
          request_headers: { Host: "api.demo.sentinel.sec", Accept: "application/json" },
          response_status: 200,
          response_headers: { "Content-Type": "application/json", Server: "FinTech-PaymentGateway/2.4.0-DEBUG" },
          response_body_snippet: JSON.stringify({
            debug_mode: true,
            database: "postgresql://payments_app:Secr3tP@ss!@postgres-db.internal:5432/fintech_db",
            internal_ip: "10.0.4.15",
          }),
          redacted_proof: "Extracted internal database URI containing unmasked authentication credentials.",
          curl_command: "curl -i https://sentinel.sec/api/demo/admin/debug",
        },
        comments: [
          {
            id: "comm-001",
            user_id: analystId,
            user_name: "Elena Rostova",
            comment_text: "Confirmed live on staging environment. Alert triggered to backend team for hotfix.",
            created_at: twoHoursAgo,
          },
        ],
      },
      {
        id: finding2Id,
        scan_id: scanId,
        api_id: demoApiId,
        api_name: "FinTech Payments API (Demo Lab)",
        endpoint_id: "ep-002",
        title: "Broken Object Level Authorization (BOLA / IDOR) on User Details",
        severity: "HIGH",
        cvss_score: 8.5,
        risk_score: 8.5,
        confidence: "CERTAIN",
        http_method: "GET",
        affected_endpoint_path: "/api/v1/users/{user_id}",
        description:
          "Supplying incremental or altered user_id path parameter allows an unauthenticated client to retrieve full names, email addresses, and account balances of other users.",
        risk_explanation:
          "Direct breach of customer confidentiality and compliance violation (GDPR, PCI-DSS requirement 3.4).",
        remediation:
          "Enforce tenant-context authorization checks verifying session ownership matches requested record before querying data store.",
        references: ["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
        owasp_category: "API1:2023 Broken Object Level Authorization",
        cwe_id: "CWE-639",
        nist_control: "AC-6",
        status: "IN_REVIEW",
        scanner_name: "BOLAAnalyzer",
        assignee_id: devId,
        assignee_name: "David Chen (Lead Backend Dev)",
        first_detected_at: twoHoursAgo,
        last_detected_at: twoHoursAgo,
        created_at: twoHoursAgo,
        evidence: {
          id: "ev-002",
          request_headers: { Host: "api.demo.sentinel.sec" },
          response_status: 200,
          response_headers: { "Content-Type": "application/json" },
          response_body_snippet: JSON.stringify({
            id: 2,
            name: "Bob Martinez",
            email: "bob@fintech.example",
            balance: 340.0,
          }),
          redacted_proof: "User ID parameter tampering yielded other accounts without authentication.",
          curl_command: "curl -i https://sentinel.sec/api/demo/users/2",
        },
      },
      {
        id: finding3Id,
        scan_id: scanId,
        api_id: demoApiId,
        api_name: "FinTech Payments API (Demo Lab)",
        endpoint_id: "ep-001",
        title: "Overly Permissive Dynamic CORS Origin Reflection with Credentials",
        severity: "HIGH",
        cvss_score: 7.5,
        risk_score: 7.5,
        confidence: "HIGH",
        http_method: "GET",
        affected_endpoint_path: "/api/v1/users",
        description:
          "The server dynamically echoes any arbitrary Origin header value into Access-Control-Allow-Origin while setting Access-Control-Allow-Credentials: true.",
        risk_explanation:
          "Any malicious external website can execute authenticated cross-origin requests and read sensitive payment responses.",
        remediation:
          "Replace dynamic reflection with an explicit strict whitelist of allowed production web domains.",
        references: ["https://owasp.org/API-Security/editions/2023/en/0xa7-security-misconfiguration/"],
        owasp_category: "API7:2023 Security Misconfiguration",
        cwe_id: "CWE-942",
        nist_control: "SC-7",
        status: "OPEN",
        scanner_name: "CORSAuditor",
        first_detected_at: twoHoursAgo,
        last_detected_at: twoHoursAgo,
        created_at: twoHoursAgo,
      },
      {
        id: finding4Id,
        scan_id: scanId,
        api_id: demoApiId,
        api_name: "FinTech Payments API (Demo Lab)",
        endpoint_id: "ep-001",
        title: "Missing Security Headers (HSTS, Content-Security-Policy, X-Content-Type)",
        severity: "MEDIUM",
        cvss_score: 5.3,
        risk_score: 5.3,
        confidence: "CERTAIN",
        http_method: "GET",
        affected_endpoint_path: "/api/v1/users",
        description:
          "Essential defensive HTTP security headers are absent, allowing protocol downgrade and MIME-type sniffing.",
        risk_explanation:
          "Exposes users on untrusted networks to Man-in-the-Middle eavesdropping and clickjacking.",
        remediation:
          "Include Strict-Transport-Security: max-age=63072000; includeSubDomains and X-Content-Type-Options: nosniff headers.",
        references: ["https://owasp.org/API-Security/editions/2023/en/0xa7-security-misconfiguration/"],
        owasp_category: "API7:2023 Security Misconfiguration",
        cwe_id: "CWE-693",
        nist_control: "SC-8",
        status: "CONFIRMED",
        scanner_name: "HeaderSecurityProbe",
        first_detected_at: twoHoursAgo,
        last_detected_at: twoHoursAgo,
        created_at: twoHoursAgo,
      },
    ];

    this.findings = findingsList;

    this.scans = [
      {
        id: scanId,
        api_id: demoApiId,
        api_name: "FinTech Payments API (Demo Lab)",
        profile_type: "STANDARD",
        profile_name: "OWASP API Top 10 Deep Audit",
        status: "COMPLETED",
        start_time: twoHoursAgo,
        end_time: new Date(Date.parse(twoHoursAgo) + 42000).toISOString(),
        duration_seconds: 42.1,
        total_requests: 184,
        endpoints_tested: 5,
        critical_count: 1,
        high_count: 2,
        medium_count: 1,
        low_count: 0,
        info_count: 0,
        scanner_modules_executed: ["BOLAAnalyzer", "ShadowEndpointDetector", "CORSAuditor", "HeaderSecurityProbe", "RateLimitTester"],
        created_at: twoHoursAgo,
        findings: findingsList,
      },
    ];

    // 4. Monitoring Overview & Metrics
    const metrics: MetricPoint[] = [];
    for (let i = 0; i < 20; i++) {
      const ts = new Date(Date.now() - (19 - i) * 60 * 1000).toISOString();
      const latency = 120 + Math.sin(i / 2) * 35 + (i === 15 ? 450 : 0);
      metrics.push({
        timestamp: ts,
        is_available: true,
        status_code: 200,
        response_time_ms: Math.round(latency * 10) / 10,
        headers_intact: true,
        tls_valid: true,
      });
    }

    this.monitoringOverview = [
      {
        api_id: demoApiId,
        api_name: "FinTech Payments API (Demo Lab)",
        current_status: "HEALTHY",
        uptime_percentage_24h: 99.85,
        avg_latency_ms_24h: 142.3,
        p95_latency_ms_24h: 280.0,
        total_checks_24h: 96,
        failed_checks_24h: 1,
        last_check_time: now,
        metrics,
      },
      {
        api_id: authApiId,
        api_name: "Customer Identity & Auth Service",
        current_status: "HEALTHY",
        uptime_percentage_24h: 100.0,
        avg_latency_ms_24h: 68.1,
        p95_latency_ms_24h: 110.0,
        total_checks_24h: 96,
        failed_checks_24h: 0,
        last_check_time: now,
        metrics: metrics.map((m) => ({ ...m, response_time_ms: Math.round(m.response_time_ms * 0.5) })),
      },
    ];

    // 5. Anomalies
    this.anomalies = [
      {
        id: "anom-001",
        api_id: demoApiId,
        api_name: "FinTech Payments API (Demo Lab)",
        anomaly_type: "LATENCY_SPIKE",
        severity: "MEDIUM",
        baseline_value: 135.0,
        observed_value: 485.0,
        deviation_percent: 259.2,
        details: "Latency spike detected across /api/v1/orders during automated stress probe cycle.",
        timestamp: new Date(Date.now() - 45 * 60 * 1000).toISOString(),
      },
      {
        id: "anom-002",
        api_id: demoApiId,
        api_name: "FinTech Payments API (Demo Lab)",
        anomaly_type: "UNAUTHENTICATED_ACCESS",
        severity: "HIGH",
        baseline_value: 0.0,
        observed_value: 12.0,
        deviation_percent: 100.0,
        details: "Unauthenticated requests observed targeting /api/v1/admin/debug from unusual origin IP.",
        timestamp: new Date(Date.now() - 90 * 60 * 1000).toISOString(),
      },
    ];

    // 6. Alerts
    this.alerts = [
      {
        id: "alt-001",
        api_id: demoApiId,
        api_name: "FinTech Payments API (Demo Lab)",
        title: "CRITICAL: Shadow API Route Discovered (/api/v1/admin/debug)",
        alert_type: "SECURITY_FINDING",
        severity: "CRITICAL",
        status: "TRIGGERED",
        description: "Publicly accessible endpoint exposing staging database connection strings and secrets.",
        recommended_action: "Immediately revoke database credentials and block route in API gateway configuration.",
        created_at: twoHoursAgo,
      },
      {
        id: "alt-002",
        api_id: demoApiId,
        api_name: "FinTech Payments API (Demo Lab)",
        title: "HIGH: Broken Object Level Authorization on /users/{id}",
        alert_type: "VULNERABILITY_THRESHOLD",
        severity: "HIGH",
        status: "ACKNOWLEDGED",
        description: "User details accessible across tenant boundaries without authentication check.",
        recommended_action: "Implement user token ownership validation in backend controller.",
        assigned_user_id: devId,
        created_at: twoHoursAgo,
      },
    ];

    // 7. Reports
    this.reports = [
      {
        id: "rep-001",
        title: "Executive API Threat Landscape & OWASP Security Audit Report",
        scope: "ORGANIZATION",
        report_format: "PDF",
        summary_data: {
          total_apis: 3,
          critical_findings: 1,
          high_findings: 2,
          security_posture: "DEFICIENT",
          remediation_sla_days: 7,
        },
        content_payload: "Executive Summary: Immediate mitigation required for Shadow Debug endpoint and BOLA vulnerabilities.",
        created_at: twoHoursAgo,
      },
    ];

    // 8. Audit Logs
    this.auditLogs = [
      {
        id: "aud-001",
        user_id: adminId,
        user_email: "admin@sentinel.sec",
        action: "INITIAL_PLATFORM_SETUP",
        resource_type: "SYSTEM",
        status: "SUCCESS",
        ip_address: "127.0.0.1",
        details: { message: "API Sentinel SOC platform initialized with active threat intelligence." },
        created_at: oneDayAgo,
      },
      {
        id: "aud-002",
        user_id: analystId,
        user_email: "analyst@sentinel.sec",
        action: "EXECUTE_SCAN",
        resource_type: "SCAN",
        resource_id: scanId,
        status: "SUCCESS",
        ip_address: "127.0.0.1",
        details: { profile: "STANDARD", target: "FinTech Payments API (Demo Lab)" },
        created_at: twoHoursAgo,
      },
    ];
  }

  // Dashboard Stats
  public getDashboardStats(): DashboardStats {
    const totalApis = this.apis.length;
    const monitoredApis = this.apis.filter((a) => a.monitoring_status === "ENABLED").length;
    const criticalVulns = this.findings.filter((f) => f.severity === "CRITICAL" && f.status !== "REMEDIATED").length;
    const highVulns = this.findings.filter((f) => f.severity === "HIGH" && f.status !== "REMEDIATED").length;
    const openFindings = this.findings.filter((f) => f.status !== "REMEDIATED").length;

    const avgScore = totalApis > 0 ? this.apis.reduce((acc, a) => acc + a.security_score, 0) / totalApis : 100;

    return {
      total_apis: totalApis,
      monitored_apis: monitoredApis,
      critical_vulnerabilities: criticalVulns,
      high_vulnerabilities: highVulns,
      open_findings: openFindings,
      average_security_score: Math.round(avgScore * 10) / 10,
      overall_availability: 99.85,
      active_alerts: this.alerts.filter((a) => a.status === "TRIGGERED").length,
      severity_distribution: {
        critical: this.findings.filter((f) => f.severity === "CRITICAL").length,
        high: this.findings.filter((f) => f.severity === "HIGH").length,
        medium: this.findings.filter((f) => f.severity === "MEDIUM").length,
        low: this.findings.filter((f) => f.severity === "LOW").length,
        informational: this.findings.filter((f) => f.severity === "INFORMATIONAL").length,
      },
      vulnerability_trends: [
        { date: "Oct 1", critical: 2, high: 3, medium: 2, low: 1 },
        { date: "Oct 2", critical: 2, high: 2, medium: 2, low: 1 },
        { date: "Oct 3", critical: 1, high: 2, medium: 1, low: 0 },
        { date: "Oct 4", critical: criticalVulns, high: highVulns, medium: 1, low: 0 },
      ],
      top_risks: this.apis.map((a) => ({
        id: a.id,
        name: a.name,
        environment: a.environment,
        security_score: a.security_score,
        critical_count: a.critical_vulns,
        high_count: a.high_vulns,
        risk_level: a.risk_classification,
      })),
      recent_scans: this.scans.map((s) => ({
        id: s.id,
        api_name: s.api_name || "API Target",
        profile_name: s.profile_name,
        status: s.status,
        duration_seconds: s.duration_seconds,
        critical_count: s.critical_count,
        high_count: s.high_count,
        medium_count: s.medium_count,
        created_at: s.created_at,
      })),
    };
  }
}

// Global Singleton for in-memory persistence in Node/Vercel Lambda
const globalSentinel = global as unknown as { __sentinelStore?: SentinelStore };
if (!globalSentinel.__sentinelStore) {
  globalSentinel.__sentinelStore = new SentinelStore();
}

export const store = globalSentinel.__sentinelStore;
