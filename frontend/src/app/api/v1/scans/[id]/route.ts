import { NextRequest } from "next/server";
import { store } from "@/lib/store";
import { apiSuccess, apiError, handleApiError } from "@/lib/auth";

export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    const scan = store.scans.find((s) => s.id === params.id);
    if (!scan) {
      return apiError("Scan not found", 404, "NOT_FOUND");
    }
    const findings = store.findings.filter((f) => f.scan_id === params.id);
    return apiSuccess({ ...scan, findings });
  } catch (err: any) {
    return handleApiError(err);
  }
}
