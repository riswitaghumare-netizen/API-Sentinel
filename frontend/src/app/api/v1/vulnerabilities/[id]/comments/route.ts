import { NextRequest } from "next/server";
import { store, generateId } from "@/lib/store";
import { apiSuccess, apiError, handleApiError, getCurrentUser, logAudit } from "@/lib/auth";

export async function POST(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    const body = await request.json();
    const { comment_text } = body;

    if (!comment_text || !comment_text.trim()) {
      return apiError("comment_text is required", 422, "VALIDATION_ERROR");
    }

    const finding = store.findings.find((f) => f.id === params.id);
    if (!finding) {
      return apiError("Finding not found", 404, "NOT_FOUND");
    }

    const user = getCurrentUser(request);
    const commentId = generateId();
    const newComment = {
      id: commentId,
      user_id: user?.id || "u-analyst-002",
      user_name: user?.full_name || "Elena Rostova",
      comment_text: comment_text.trim(),
      created_at: new Date().toISOString(),
    };

    if (!finding.comments) {
      finding.comments = [];
    }
    finding.comments.push(newComment);

    logAudit(user?.id || null, user?.email || null, "ADD_VULNERABILITY_COMMENT", "FINDING", params.id, {
      comment_id: commentId,
    });

    return apiSuccess(newComment, 201);
  } catch (err: any) {
    return handleApiError(err);
  }
}
