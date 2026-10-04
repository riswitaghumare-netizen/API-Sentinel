import { NextRequest } from "next/server";
import { store, generateId } from "@/lib/store";
import { apiSuccess, handleApiError, getCurrentUser, logAudit } from "@/lib/auth";
import { SecurityReport } from "@/lib/types";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json().catch(() => ({}));
    const user = getCurrentUser(request);
    const id = generateId();
    const now = new Date().toISOString();

    const critCount = store.findings.filter((f) => f.severity === "CRITICAL").length;
    const highCount = store.findings.filter((f) => f.severity === "HIGH").length;

    const newReport: SecurityReport = {
      id,
      title: body.title || `API Security Assessment Report - ${new Date().toLocaleDateString()}`,
      scope: body.scope || "ORGANIZATION",
      target_id: body.target_id,
      report_format: body.report_format || "PDF",
      summary_data: {
        total_apis_evaluated: store.apis.length,
        critical_vulnerabilities: critCount,
        high_vulnerabilities: highCount,
        compliance_frameworks: ["OWASP API Security Top 10", "PCI-DSS 4.0", "NIST SP 800-53"],
        posture_status: critCount > 0 ? "ACTION_REQUIRED" : "SECURE",
      },
      content_payload: `Automated Executive Threat Analysis generated for Sentinel Cyber Defense. Evaluated ${store.apis.length} registered APIs with ${store.findings.length} findings tracked.`,
      created_at: now,
    };

    store.reports.unshift(newReport);

    logAudit(user?.id || null, user?.email || null, "GENERATE_SECURITY_REPORT", "REPORT", id, {
      title: newReport.title,
      format: newReport.report_format,
    });

    return apiSuccess(newReport, 201);
  } catch (err: any) {
    return handleApiError(err);
  }
}
