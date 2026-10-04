import { NextRequest } from "next/server";
import { store, generateId } from "@/lib/store";
import { apiSuccess, handleApiError, logAudit, getCurrentUser } from "@/lib/auth";
import { APIDetail, APITarget } from "@/lib/types";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const environment = searchParams.get("environment");
    const risk = searchParams.get("risk");
    const search = searchParams.get("search");

    let apis = store.apis.map((a) => {
      const { endpoints, credentials, ...summary } = a;
      return summary as APITarget;
    });

    if (environment) {
      apis = apis.filter((a) => a.environment === environment);
    }
    if (risk) {
      apis = apis.filter((a) => a.risk_classification === risk);
    }
    if (search) {
      const term = search.toLowerCase();
      apis = apis.filter(
        (a) => a.name.toLowerCase().includes(term) || a.base_url.toLowerCase().includes(term)
      );
    }

    return apiSuccess(apis);
  } catch (err: any) {
    return handleApiError(err);
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const user = getCurrentUser(request);
    const id = generateId();
    const now = new Date().toISOString();

    const newApi: APIDetail = {
      id,
      project_id: body.project_id || "proj-001",
      name: body.name || "New API Target",
      description: body.description || "",
      base_url: body.base_url || "https://api.example.com",
      environment: body.environment || "DEVELOPMENT",
      owner: body.owner || user?.full_name || "Security Operations",
      team: body.team || "Engineering",
      tags: body.tags || [],
      technology: body.technology || "REST / JSON",
      version: body.version || "v1.0.0",
      monitoring_status: "ENABLED",
      risk_classification: "MEDIUM",
      security_score: 100.0,
      health_status: "HEALTHY",
      endpoints_count: 0,
      open_vulnerabilities_count: 0,
      critical_vulns: 0,
      high_vulns: 0,
      medium_vulns: 0,
      low_vulns: 0,
      info_vulns: 0,
      created_at: now,
      endpoints: [],
      credentials: [],
    };

    store.apis.unshift(newApi);

    // Also add to monitoring overview
    store.monitoringOverview.unshift({
      api_id: id,
      api_name: newApi.name,
      current_status: "HEALTHY",
      uptime_percentage_24h: 100.0,
      avg_latency_ms_24h: 45.0,
      p95_latency_ms_24h: 80.0,
      total_checks_24h: 1,
      failed_checks_24h: 0,
      last_check_time: now,
      metrics: [
        {
          timestamp: now,
          is_available: true,
          status_code: 200,
          response_time_ms: 45.0,
          headers_intact: true,
          tls_valid: true,
        },
      ],
    });

    logAudit(user?.id || null, user?.email || null, "CREATE_API_TARGET", "API_TARGET", id, {
      name: newApi.name,
      base_url: newApi.base_url,
    });

    return apiSuccess(newApi, 201);
  } catch (err: any) {
    return handleApiError(err);
  }
}
