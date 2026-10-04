import { NextRequest } from "next/server";
import { store, generateId } from "@/lib/store";
import { apiSuccess, apiError, handleApiError, logAudit, getCurrentUser } from "@/lib/auth";
import { APIDetail, APIEndpoint } from "@/lib/types";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { spec_content, base_url_override } = body;

    if (!spec_content) {
      return apiError("spec_content is required", 422, "VALIDATION_ERROR");
    }

    let parsed: any;
    try {
      parsed = JSON.parse(spec_content);
    } catch {
      return apiError("Invalid OpenAPI JSON format", 400, "INVALID_FORMAT");
    }

    const title = parsed.info?.title || "Imported API Specification";
    const version = parsed.info?.version || "v1.0.0";
    const baseUrl = base_url_override || (parsed.servers && parsed.servers[0]?.url) || "https://api.imported.example";

    const endpoints: APIEndpoint[] = [];
    if (parsed.paths) {
      for (const [path, methods] of Object.entries(parsed.paths as Record<string, any>)) {
        for (const [method, details] of Object.entries(methods as Record<string, any>)) {
          if (["get", "post", "put", "delete", "patch"].includes(method.toLowerCase())) {
            endpoints.push({
              id: generateId(),
              path,
              method: method.toUpperCase(),
              summary: details.summary || `${method.toUpperCase()} ${path}`,
              parameters: (details.parameters || []).map((p: any) => ({
                name: p.name,
                in: p.in || "query",
                required: !!p.required,
                type: p.schema?.type || "string",
              })),
              request_body_schema: details.requestBody || {},
              responses_schema: details.responses || {},
              is_authenticated: !!(details.security && details.security.length > 0),
              auth_type: details.security ? "BEARER_TOKEN" : "NONE",
              is_deprecated: !!details.deprecated,
              tags: details.tags || ["imported"],
            });
          }
        }
      }
    }

    const apiId = generateId();
    const now = new Date().toISOString();

    const newApi: APIDetail = {
      id: apiId,
      project_id: "proj-001",
      name: title,
      description: parsed.info?.description || "OpenAPI 3.0 Imported Service",
      base_url: baseUrl,
      environment: "DEVELOPMENT",
      owner: "SecOps Lead",
      team: "Platform Engineering",
      tags: ["openapi-imported", version],
      technology: "OpenAPI 3.0 / REST",
      version,
      monitoring_status: "ENABLED",
      risk_classification: "MEDIUM",
      security_score: 95.0,
      health_status: "HEALTHY",
      endpoints_count: endpoints.length,
      open_vulnerabilities_count: 0,
      critical_vulns: 0,
      high_vulns: 0,
      medium_vulns: 0,
      low_vulns: 0,
      info_vulns: 0,
      created_at: now,
      endpoints,
      credentials: [],
    };

    store.apis.unshift(newApi);

    const user = getCurrentUser(request);
    logAudit(user?.id || null, user?.email || null, "IMPORT_OPENAPI", "API_TARGET", apiId, {
      title,
      endpoints_count: endpoints.length,
    });

    return apiSuccess(newApi, 201);
  } catch (err: any) {
    return handleApiError(err);
  }
}
