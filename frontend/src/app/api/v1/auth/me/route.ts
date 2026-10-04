import { NextRequest } from "next/server";
import { getCurrentUser, apiSuccess, apiError, handleApiError } from "@/lib/auth";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  try {
    const user = getCurrentUser(request);
    if (!user) {
      return apiError("Unauthorized", 401, "UNAUTHORIZED");
    }
    return apiSuccess(user);
  } catch (err: any) {
    return handleApiError(err);
  }
}
