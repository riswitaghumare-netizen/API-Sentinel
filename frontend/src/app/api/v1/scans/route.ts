import { NextRequest } from "next/server";
import { store, generateId } from "@/lib/store";
import { apiSuccess, apiError, handleApiError, logAudit, getCurrentUser } from "@/lib/auth";
import { Scan, ScanFinding } from "@/lib/types";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const apiId = searchParams.get("api_id");

    let scans = store.scans;
    if (apiId) {
      scans = scans.filter((s) => s.api_id === apiId);
    }

    return apiSuccess(scans);
  } catch (err: any) {
    return handleApiError(err);
  }
}

export async function POST(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const apiId = searchParams.get("api_id");
    const body = await request.json().catch(() => ({}));
    const profileType = body.profile_type || "STANDARD";

    if (!apiId) {
      return apiError("api_id query parameter is required", 422, "VALIDATION_ERROR");
    }

    const api = store.apis.find((a) => a.id === apiId);
    if (!api) {
      return apiError("Target API not found", 404, "NOT_FOUND");
    }

    const user = getCurrentUser(request);
    const scanId = generateId();
    const now = new Date().toISOString();
    const duration = profileType === "QUICK" ? 14.5 : profileType === "DEEP" ? 68.2 : 36.4;
    const reqCount = profileType === "QUICK" ? 64 : profileType === "DEEP" ? 380 : 184;

    // Generate scan findings for the target
    const newFindings: ScanFinding[] = [];

    if (api.base_url.includes("demo") || api.id === "api-demo-001" || api.name.toLowerCase().includes("demo")) {
      newFindings.push({
        id: generateId(),
        scan_id: scanId,
        api_id: api.id,
        api_name: api.name,
        title: "Unauthenticated Shadow API Endpoint Exposing Internal Secrets",
        severity: "CRITICAL",
        cvss_score: 9.8,
        risk_score: 9.8,
        confidence: "CERTAIN",
        http_method: "GET",
        affected_endpoint_path: "/api/v1/admin/debug",
        description: "The endpoint /api/v1/admin/debug responds without authentication disclosing database credentials and staging topology.",
        risk_explanation: "Allows lateral network movement and complete database credential extraction.",
        remediation: "Immediately deprecate endpoint or restrict access behind mTLS and IP allowlist.",
        references: ["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
        owasp_category: "API9:2023 Improper Inventory Management",
        cwe_id: "CWE-200",
        nist_control: "AC-3 / CM-8",
        status: "OPEN",
        scanner_name: "ShadowEndpointDetector",
        first_detected_at: now,
        last_detected_at: now,
        created_at: now,
        evidence: {
          id: generateId(),
          request_headers: { Host: "api-sentinel.local" },
          response_status: 200,
          response_headers: { "Content-Type": "application/json" },
          response_body_snippet: JSON.stringify({ debug_mode: true, db: "postgres-cluster" }),
          redacted_proof: "Shadow endpoint confirmed accessible.",
          curl_command: `curl -i ${api.base_url}/admin/debug`,
        },
      });

      newFindings.push({
        id: generateId(),
        scan_id: scanId,
        api_id: api.id,
        api_name: api.name,
        title: "Broken Object Level Authorization (BOLA / IDOR) on User Profile",
        severity: "HIGH",
        cvss_score: 8.5,
        risk_score: 8.5,
        confidence: "CERTAIN",
        http_method: "GET",
        affected_endpoint_path: "/api/v1/users/{user_id}",
        description: "Altered user_id parameters permit access to unauthorized customer balance and personally identifiable information.",
        risk_explanation: "Exposes sensitive customer records without authentication verification.",
        remediation: "Validate caller token identity against requested resource ownership context.",
        references: ["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
        owasp_category: "API1:2023 Broken Object Level Authorization",
        cwe_id: "CWE-639",
        nist_control: "AC-6",
        status: "OPEN",
        scanner_name: "BOLAAnalyzer",
        first_detected_at: now,
        last_detected_at: now,
        created_at: now,
      });

      newFindings.push({
        id: generateId(),
        scan_id: scanId,
        api_id: api.id,
        api_name: api.name,
        title: "Dynamic Cross-Origin Resource Sharing (CORS) with Credentials Allowed",
        severity: "HIGH",
        cvss_score: 7.5,
        risk_score: 7.5,
        confidence: "HIGH",
        http_method: "GET",
        affected_endpoint_path: "/api/v1/users",
        description: "Dynamic origin echoing permits arbitrary external domains to read customer data.",
        risk_explanation: "Enables cross-origin data exfiltration attacks from unauthorized web origins.",
        remediation: "Specify explicit static origin whitelist.",
        references: ["https://owasp.org/API-Security/editions/2023/en/0xa7-security-misconfiguration/"],
        owasp_category: "API7:2023 Security Misconfiguration",
        cwe_id: "CWE-942",
        nist_control: "SC-7",
        status: "OPEN",
        scanner_name: "CORSAuditor",
        first_detected_at: now,
        last_detected_at: now,
        created_at: now,
      });
    } else {
      // Generic finding for other APIs
      newFindings.push({
        id: generateId(),
        scan_id: scanId,
        api_id: api.id,
        api_name: api.name,
        title: "Missing Strict-Transport-Security (HSTS) Header",
        severity: "MEDIUM",
        cvss_score: 5.3,
        risk_score: 5.3,
        confidence: "CERTAIN",
        http_method: "GET",
        affected_endpoint_path: "/",
        description: "The endpoint does not enforce HTTPS via Strict-Transport-Security headers.",
        risk_explanation: "Leaves connection susceptible to SSL stripping attacks.",
        remediation: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains header.",
        references: ["https://owasp.org/API-Security/editions/2023/en/0xa7-security-misconfiguration/"],
        owasp_category: "API7:2023 Security Misconfiguration",
        cwe_id: "CWE-693",
        nist_control: "SC-8",
        status: "OPEN",
        scanner_name: "HeaderSecurityProbe",
        first_detected_at: now,
        last_detected_at: now,
        created_at: now,
      });
    }

    const critCount = newFindings.filter((f) => f.severity === "CRITICAL").length;
    const highCount = newFindings.filter((f) => f.severity === "HIGH").length;
    const medCount = newFindings.filter((f) => f.severity === "MEDIUM").length;

    const newScan: Scan = {
      id: scanId,
      api_id: api.id,
      api_name: api.name,
      profile_type: profileType,
      profile_name: profileType === "QUICK" ? "Rapid Smoke Scan" : profileType === "DEEP" ? "Deep OWASP API Pentest" : "Standard Security Audit",
      status: "COMPLETED",
      start_time: now,
      end_time: new Date(Date.now() + duration * 1000).toISOString(),
      duration_seconds: duration,
      total_requests: reqCount,
      endpoints_tested: Math.max(api.endpoints_count, 4),
      critical_count: critCount,
      high_count: highCount,
      medium_count: medCount,
      low_count: 0,
      info_count: 0,
      scanner_modules_executed: ["BOLAAnalyzer", "ShadowEndpointDetector", "CORSAuditor", "HeaderSecurityProbe"],
      created_at: now,
      findings: newFindings,
    };

    // Prepend to store
    store.scans.unshift(newScan);
    store.findings.unshift(...newFindings);

    // Update target API metrics
    api.last_scanned_at = now;
    api.critical_vulns = critCount;
    api.high_vulns = highCount;
    api.medium_vulns = medCount;
    api.open_vulnerabilities_count = newFindings.length;
    api.security_score = Math.max(20, 100 - critCount * 25 - highCount * 12 - medCount * 5);

    logAudit(user?.id || null, user?.email || null, "TRIGGER_SCAN", "SCAN", scanId, {
      api_id: api.id,
      api_name: api.name,
      profile: profileType,
      findings_discovered: newFindings.length,
    });

    return apiSuccess(newScan, 201);
  } catch (err: any) {
    return handleApiError(err);
  }
}
