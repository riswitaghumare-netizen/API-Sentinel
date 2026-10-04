import { NextRequest } from "next/server";
import { store } from "@/lib/store";
import {
  verifyPassword,
  createAccessToken,
  createRefreshToken,
  apiSuccess,
  apiError,
  handleApiError,
  logAudit,
} from "@/lib/auth";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { email, password } = body;

    if (!email || !password) {
      return apiError("Email and password are required.", 422, "VALIDATION_ERROR");
    }

    const user = store.users.find((u) => u.email.toLowerCase() === email.toLowerCase());
    if (!user || !user.is_active) {
      return apiError("Invalid credentials or account disabled.", 401, "INVALID_CREDENTIALS");
    }

    const isValid = verifyPassword(password, user.hashed_password);
    if (!isValid) {
      return apiError("Invalid credentials.", 401, "INVALID_CREDENTIALS");
    }

    const accessToken = createAccessToken(user.id, user.role, user.organization_id);
    const refreshToken = createRefreshToken(user.id);

    logAudit(user.id, user.email, "USER_LOGIN", "USER", user.id, {
      method: "PASSWORD",
      ip: "127.0.0.1",
    });

    const { hashed_password, ...safeUser } = user;

    return apiSuccess({
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: "bearer",
      user: safeUser,
    });
  } catch (err: any) {
    return handleApiError(err);
  }
}
