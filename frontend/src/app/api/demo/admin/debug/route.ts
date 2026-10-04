import { NextResponse } from "next/server";

// Intentionally vulnerable unauthenticated debug endpoint (Shadow API)
export async function GET() {
  return NextResponse.json(
    {
      debug_mode: true,
      environment: "staging-sandbox",
      internal_ip: "10.0.4.15",
      database: "postgresql://payments_app:Secr3tP@ss!@postgres-db.internal:5432/fintech_db",
      loaded_modules: ["auth_v2", "stripe_gateway", "risk_engine"],
    },
    {
      headers: {
        "Server": "FinTech-PaymentGateway/2.4.0-DEBUG",
        "X-Debug-Trace": "TraceID-8849-Enabled",
      },
    }
  );
}
