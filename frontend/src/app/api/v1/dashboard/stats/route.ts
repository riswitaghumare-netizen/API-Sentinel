import { NextRequest } from "next/server";
import { store } from "@/lib/store";
import { apiSuccess, handleApiError } from "@/lib/auth";

export async function GET(request: NextRequest) {
  try {
    const stats = store.getDashboardStats();
    return apiSuccess(stats);
  } catch (err: any) {
    return handleApiError(err);
  }
}
