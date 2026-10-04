import { NextRequest } from "next/server";
import { store } from "@/lib/store";
import { apiSuccess, handleApiError } from "@/lib/auth";

export async function GET(request: NextRequest) {
  try {
    return apiSuccess(store.reports);
  } catch (err: any) {
    return handleApiError(err);
  }
}
