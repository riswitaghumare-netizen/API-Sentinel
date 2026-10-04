import { NextRequest } from "next/server";
import { store } from "@/lib/store";
import { apiSuccess, handleApiError } from "@/lib/auth";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const apiId = searchParams.get("api_id");

    let anomalies = store.anomalies;
    if (apiId) {
      anomalies = anomalies.filter((a) => a.api_id === apiId);
    }

    return apiSuccess(anomalies);
  } catch (err: any) {
    return handleApiError(err);
  }
}
