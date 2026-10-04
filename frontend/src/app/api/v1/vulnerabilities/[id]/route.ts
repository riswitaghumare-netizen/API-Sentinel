import { NextRequest } from "next/server";
import { store } from "@/lib/store";
import { apiSuccess, apiError, handleApiError, logAudit, getCurrentUser } from "@/lib/auth";

export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    const finding = store.findings.find((f) => f.id === params.id);
    if (!finding) {
      return apiError("Finding not found", 404, "NOT_FOUND");
    }
    return apiSuccess(finding);
  } catch (err: any) {
    return handleApiError(err);
  }
}

export async function PUT(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    const body = await request.json();
    const finding = store.findings.find((f) => f.id === params.id);
    if (!finding) {
      return apiError("Finding not found", 404, "NOT_FOUND");
    }

    const user = getCurrentUser(request);

    if (body.status) finding.status = body.status;
    if (body.assignee_id) {
      finding.assignee_id = body.assignee_id;
      const assigned = store.users.find((u) => u.id === body.assignee_id);
      if (assigned) finding.assignee_name = assigned.full_name;
    }
    if (body.due_date) finding.due_date = body.due_date;
    finding.last_detected_at = new Date().toISOString();

    logAudit(user?.id || null, user?.email || null, "UPDATE_VULNERABILITY", "FINDING", params.id, {
      title: finding.title,
      new_status: finding.status,
    });

    return apiSuccess(finding);
  } catch (err: any) {
    return handleApiError(err);
  }
}
