import { NextRequest, NextResponse } from "next/server";

export async function POST(request: NextRequest) {
  const payload = await request.json().catch(() => ({}));
  return NextResponse.json({
    received: payload,
    echo_status: "ok",
    timestamp: new Date().toISOString(),
  });
}
