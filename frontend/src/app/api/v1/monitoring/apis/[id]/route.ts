import { NextRequest } from "next/server";
import { store } from "@/lib/store";
import { apiSuccess, apiError, handleApiError } from "@/lib/auth";

export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    const item = store.monitoringOverview.find((m) => m.api_id === params.id);
    if (!item) {
      return apiError("Monitoring data not found for API", 404, "NOT_FOUND");
    }
    return apiSuccess(item);
  } catch (err: any) {
    return handleApiError(err);
  }
}
