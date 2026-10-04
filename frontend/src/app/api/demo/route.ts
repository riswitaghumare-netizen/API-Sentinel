import { NextResponse } from "next/server";

export async function GET() {
  return NextResponse.json(
    {
      service: "FinTech Payments API (Demo Target)",
      status: "operational",
      version: "v2.4.0",
      description: "Intentionally vulnerable test API for defensive security scanning verification.",
    },
    {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Server": "FinTech-PaymentGateway/2.4.0-DEBUG",
        "X-Debug-Trace": "TraceID-8849-Enabled",
      },
    }
  );
}
