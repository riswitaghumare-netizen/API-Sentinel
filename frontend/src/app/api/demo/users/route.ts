import { NextRequest, NextResponse } from "next/server";

const DEMO_USERS = [
  { id: 1, name: "Alice Johnson", email: "alice@fintech.example", role: "admin", balance: 15420.5 },
  { id: 2, name: "Bob Martinez", email: "bob@fintech.example", role: "customer", balance: 340.0 },
  { id: 3, name: "Charlie Davis", email: "charlie@fintech.example", role: "customer", balance: 2800.75 },
];

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const origin = request.headers.get("origin") || "*";
  return NextResponse.json(
    { users: DEMO_USERS, total: DEMO_USERS.length },
    {
      headers: {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
        "Server": "FinTech-PaymentGateway/2.4.0-DEBUG",
      },
    }
  );
}
