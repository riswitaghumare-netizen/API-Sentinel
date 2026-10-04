import { NextRequest } from "next/server";
import { store } from "@/lib/store";
import { apiSuccess, apiError, handleApiError } from "@/lib/auth";

export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    const report = store.reports.find((r) => r.id === params.id);
    if (!report) {
      return apiError("Report not found", 404, "NOT_FOUND");
    }
    return apiSuccess(report);
  } catch (err: any) {
    return handleApiError(err);
  }
}
