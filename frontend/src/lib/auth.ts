import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { NextRequest } from "next/server";
import { store, generateId, StoredUser } from "./store";
import { User } from "./types";

const SECRET_KEY = process.env.SECRET_KEY || "api-sentinel-ultra-secure-secret-key-change-in-production-32bytes";
const ALGORITHM = "HS256";
const ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24; // 24 hours

export function verifyPassword(plain: string, hashed: string): boolean {
  if (!plain || !hashed) return false;
  try {
    return bcrypt.compareSync(plain, hashed);
  } catch {
    return false;
  }
}

export function hashPassword(password: string): string {
  return bcrypt.hashSync(password, 10);
}

export function createAccessToken(userId: string, role: string, orgId?: string | null): string {
  return jwt.sign(
    { sub: userId, role, org_id: orgId || null, type: "access", iat: Math.floor(Date.now() / 1000) },
    SECRET_KEY,
    { algorithm: ALGORITHM, expiresIn: ACCESS_TOKEN_EXPIRE_MINUTES * 60 }
  );
}

export function createRefreshToken(userId: string): string {
  return jwt.sign(
    { sub: userId, type: "refresh", iat: Math.floor(Date.now() / 1000) },
    SECRET_KEY,
    { algorithm: ALGORITHM, expiresIn: "7d" }
  );
}

export function decodeToken(token: string): any | null {
  try {
    return jwt.verify(token, SECRET_KEY, { algorithms: [ALGORITHM] });
  } catch {
    return null;
  }
}

export function getCurrentUser(request: NextRequest): User | null {
  const authHeader = request.headers.get("authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  const token = authHeader.substring(7);
  const payload = decodeToken(token);
  if (!payload || payload.type !== "access") return null;

  const user = store.users.find((u) => u.id === payload.sub);
  if (!user || !user.is_active) return null;
  const { hashed_password, ...safeUser } = user;
  return safeUser;
}

export function requireAuth(request: NextRequest): User {
  const user = getCurrentUser(request);
  if (!user) throw new Error("UNAUTHORIZED");
  return user;
}

// Standard API response helpers
export function apiSuccess(data: any, status = 200) {
  return Response.json({ success: true, data }, { status });
}

export function apiError(message: string, status = 400, code = "BAD_REQUEST") {
  return Response.json({ success: false, error: { code, message } }, { status });
}

export function handleApiError(err: any) {
  if (err?.message === "UNAUTHORIZED") return apiError("Authentication required.", 401, "UNAUTHORIZED");
  if (err?.message === "FORBIDDEN") return apiError("Insufficient permissions.", 403, "FORBIDDEN");
  console.error("API Error:", err);
  return apiError(err?.message || "An internal server error occurred.", 500, "INTERNAL_SERVER_ERROR");
}

export function logAudit(
  userId: string | null,
  email: string | null,
  action: string,
  resourceType: string,
  resourceId?: string | null,
  details?: any
) {
  store.auditLogs.unshift({
    id: generateId(),
    user_id: userId || undefined,
    user_email: email || undefined,
    action,
    resource_type: resourceType,
    resource_id: resourceId || undefined,
    status: "SUCCESS",
    details: details || {},
    created_at: new Date().toISOString(),
  });
}
