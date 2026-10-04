import { NextRequest } from "next/server";
import { store, generateId } from "@/lib/store";
import {
  hashPassword,
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
    const { email, password, full_name, role = "DEVELOPER" } = body;

    if (!email || !password || !full_name) {
      return apiError("Email, password, and full name are required.", 422, "VALIDATION_ERROR");
    }

    const existing = store.users.find((u) => u.email.toLowerCase() === email.toLowerCase());
    if (existing) {
      return apiError("A user with this email already exists.", 409, "USER_EXISTS");
    }

    const userId = generateId();
    const hashedPassword = hashPassword(password);
    const now = new Date().toISOString();

    const newUser = {
      id: userId,
      email,
      hashed_password: hashedPassword,
      full_name,
      role: role as any,
      is_active: true,
      created_at: now,
    };

    store.users.push(newUser);

    const accessToken = createAccessToken(userId, role);
    const refreshToken = createRefreshToken(userId);

    logAudit(userId, email, "USER_REGISTER", "USER", userId, {
      full_name,
      role,
    });

    const { hashed_password, ...safeUser } = newUser;

    return apiSuccess(
      {
        access_token: accessToken,
        refresh_token: refreshToken,
        token_type: "bearer",
        user: safeUser,
      },
      201
    );
  } catch (err: any) {
    return handleApiError(err);
  }
}
