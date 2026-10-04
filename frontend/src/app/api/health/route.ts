import { NextResponse } from "next/server";

export async function GET() {
  return NextResponse.json({
    status: "healthy",
    service: "api-sentinel-unified",
    version: "v1.0.0",
    timestamp: new Date().toISOString(),
    components: {
      frontend: "operational",
      backend_api: "operational",
      demo_target_api: "operational",
    },
  });
}
