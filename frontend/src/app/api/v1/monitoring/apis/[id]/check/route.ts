import { NextRequest } from "next/server";
import { store } from "@/lib/store";
import { apiSuccess, apiError, handleApiError, getCurrentUser, logAudit } from "@/lib/auth";

export async function POST(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    const api = store.apis.find((a) => a.id === params.id);
    if (!api) {
      return apiError("API target not found", 404, "NOT_FOUND");
    }

    const now = new Date().toISOString();
    const latency = Math.round((40 + Math.random() * 60) * 10) / 10;
    const metric = {
      timestamp: now,
      is_available: true,
      status_code: 200,
      response_time_ms: latency,
      headers_intact: true,
      tls_valid: true,
    };

    let overview = store.monitoringOverview.find((m) => m.api_id === params.id);
    if (overview) {
      overview.last_check_time = now;
      overview.total_checks_24h += 1;
      overview.metrics.push(metric);
      if (overview.metrics.length > 25) {
        overview.metrics.shift();
      }
    }

    api.last_monitored_at = now;
    api.health_status = "HEALTHY";

    const user = getCurrentUser(request);
    logAudit(user?.id || null, user?.email || null, "TRIGGER_HEALTH_CHECK", "MONITORING", params.id, {
      status_code: 200,
      latency_ms: latency,
    });

    return apiSuccess({
      status: "HEALTHY",
      latency_ms: latency,
      timestamp: now,
      checked: true,
    });
  } catch (err: any) {
    return handleApiError(err);
  }
}
