import { NextRequest } from "next/server";
import { store } from "@/lib/store";
import { apiSuccess, apiError, handleApiError, getCurrentUser, logAudit } from "@/lib/auth";

export async function PUT(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    const body = await request.json();
    const alert = store.alerts.find((a) => a.id === params.id);
    if (!alert) {
      return apiError("Alert not found", 404, "NOT_FOUND");
    }

    if (body.status) alert.status = body.status;
    if (body.assigned_user_id) alert.assigned_user_id = body.assigned_user_id;
    if (body.status === "RESOLVED") alert.resolved_at = new Date().toISOString();

    const user = getCurrentUser(request);
    logAudit(user?.id || null, user?.email || null, "UPDATE_ALERT", "ALERT", params.id, {
      title: alert.title,
      status: alert.status,
    });

    return apiSuccess(alert);
  } catch (err: any) {
    return handleApiError(err);
  }
}
