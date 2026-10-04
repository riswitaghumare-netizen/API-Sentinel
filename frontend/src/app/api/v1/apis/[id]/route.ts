import { NextRequest } from "next/server";
import { store } from "@/lib/store";
import { apiSuccess, apiError, handleApiError, logAudit, getCurrentUser } from "@/lib/auth";

export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    const api = store.apis.find((a) => a.id === params.id);
    if (!api) {
      return apiError("API target not found", 404, "NOT_FOUND");
    }
    return apiSuccess(api);
  } catch (err: any) {
    return handleApiError(err);
  }
}

export async function DELETE(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    const user = getCurrentUser(request);
    const index = store.apis.findIndex((a) => a.id === params.id);
    if (index === -1) {
      return apiError("API target not found", 404, "NOT_FOUND");
    }

    const removed = store.apis.splice(index, 1)[0];
    store.monitoringOverview = store.monitoringOverview.filter((m) => m.api_id !== params.id);

    logAudit(user?.id || null, user?.email || null, "DELETE_API_TARGET", "API_TARGET", params.id, {
      name: removed.name,
    });

    return apiSuccess({ deleted: true, id: params.id });
  } catch (err: any) {
    return handleApiError(err);
  }
}
