import { NextRequest } from "next/server";
import { store } from "@/lib/store";
import { apiSuccess, handleApiError } from "@/lib/auth";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const apiId = searchParams.get("api_id");
    const severity = searchParams.get("severity");
    const status = searchParams.get("status");

    let findings = store.findings;
    if (apiId) {
      findings = findings.filter((f) => f.api_id === apiId);
    }
    if (severity) {
      findings = findings.filter((f) => f.severity === severity);
    }
    if (status) {
      findings = findings.filter((f) => f.status === status);
    }

    return apiSuccess(findings);
  } catch (err: any) {
    return handleApiError(err);
  }
}
