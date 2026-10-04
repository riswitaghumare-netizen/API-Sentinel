import { NextRequest, NextResponse } from "next/server";

const DEMO_USERS: Record<string, any> = {
  "1": { id: 1, name: "Alice Johnson", email: "alice@fintech.example", role: "admin", balance: 15420.5 },
  "2": { id: 2, name: "Bob Martinez", email: "bob@fintech.example", role: "customer", balance: 340.0 },
  "3": { id: 3, name: "Charlie Davis", email: "charlie@fintech.example", role: "customer", balance: 2800.75 },
};

export const dynamic = "force-dynamic";

// Intentionally vulnerable to BOLA / IDOR: no session ownership check!
export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  const user = DEMO_USERS[params.id];
  if (!user) {
    return NextResponse.json({ detail: `User ${params.id} not found.` }, { status: 404 });
  }

  const origin = request.headers.get("origin") || "*";
  return NextResponse.json(user, {
    headers: {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Credentials": "true",
      "Server": "FinTech-PaymentGateway/2.4.0-DEBUG",
    },
  });
}
