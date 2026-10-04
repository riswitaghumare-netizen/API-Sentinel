import {
  User,
  APITarget,
  APIDetail,
  Scan,
  ScanFinding,
  MonitoringOverview,
  AnomalyEvent,
  AlertItem,
  DashboardStats,
  SecurityReport,
  AuditLog,
} from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

export class ApiClient {
  private static getToken(): string | null {
    if (typeof window === "undefined") return null;
    return localStorage.getItem("sentinel_token");
  }

  public static setToken(token: string) {
    if (typeof window !== "undefined") {
      localStorage.setItem("sentinel_token", token);
    }
  }

  public static clearToken() {
    if (typeof window !== "undefined") {
      localStorage.removeItem("sentinel_token");
      localStorage.removeItem("sentinel_user");
    }
  }

  private static async request<T>(
    path: string,
    options: RequestInit = {}
  ): Promise<{ success: boolean; data: T; error?: any }> {
    const token = this.getToken();
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(options.headers as Record<string, string>),
    };

    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    const url = `${API_BASE}${path}`;
    try {
      const res = await fetch(url, { ...options, headers });
      const json = await res.json();

      if (!res.ok || json.success === false) {
        throw new Error(json.error?.message || `Request failed with status ${res.status}`);
      }

      return json;
    } catch (err: any) {
      console.error(`API error on ${path}:`, err);
      throw err;
    }
  }

  // Auth
  static async login(email: string, password: string) {
    const res = await this.request<{ access_token: string; user: User }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    this.setToken(res.data.access_token);
    if (typeof window !== "undefined") {
      localStorage.setItem("sentinel_user", JSON.stringify(res.data.user));
    }
    return res.data;
  }

  static async register(payload: { email: string; password: string; full_name: string; organization_name?: string }) {
    const res = await this.request<{ access_token: string; user: User }>("/auth/register", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    this.setToken(res.data.access_token);
    if (typeof window !== "undefined") {
      localStorage.setItem("sentinel_user", JSON.stringify(res.data.user));
    }
    return res.data;
  }

  static async getMe(): Promise<User> {
    const res = await this.request<User>("/auth/me");
    return res.data;
  }

  // Dashboard
  static async getDashboardStats(): Promise<DashboardStats> {
    const res = await this.request<DashboardStats>("/dashboard/stats");
    return res.data;
  }

  // APIs
  static async getApis(params?: { environment?: string; risk?: string; search?: string }): Promise<APITarget[]> {
    let q = "";
    if (params) {
      const searchParams = new URLSearchParams();
      if (params.environment) searchParams.set("environment", params.environment);
      if (params.risk) searchParams.set("risk", params.risk);
      if (params.search) searchParams.set("search", params.search);
      const str = searchParams.toString();
      if (str) q = `?${str}`;
    }
    const res = await this.request<APITarget[]>(`/apis${q}`);
    return res.data;
  }

  static async getApiDetail(id: string): Promise<APIDetail> {
    const res = await this.request<APIDetail>(`/apis/${id}`);
    return res.data;
  }

  static async createApi(payload: any): Promise<APIDetail> {
    const res = await this.request<APIDetail>("/apis", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    return res.data;
  }

  static async importOpenAPI(specContent: string, baseUrlOverride?: string): Promise<APIDetail> {
    const res = await this.request<APIDetail>("/apis/import-openapi", {
      method: "POST",
      body: JSON.stringify({ spec_content: specContent, base_url_override: baseUrlOverride }),
    });
    return res.data;
  }

  static async deleteApi(id: string): Promise<void> {
    await this.request(`/apis/${id}`, { method: "DELETE" });
  }

  // Scans
  static async triggerScan(apiId: string, profileType: string = "STANDARD"): Promise<Scan> {
    const res = await this.request<Scan>(`/scans?api_id=${apiId}`, {
      method: "POST",
      body: JSON.stringify({ profile_type: profileType }),
    });
    return res.data;
  }

  static async getScans(apiId?: string): Promise<Scan[]> {
    const q = apiId ? `?api_id=${apiId}` : "";
    const res = await this.request<Scan[]>(`/scans${q}`);
    return res.data;
  }

  static async getScanDetail(scanId: string): Promise<Scan> {
    const res = await this.request<Scan>(`/scans/${scanId}`);
    return res.data;
  }

  // Findings
  static async getVulnerabilities(params?: { api_id?: string; severity?: string; status?: string }): Promise<ScanFinding[]> {
    let q = "";
    if (params) {
      const searchParams = new URLSearchParams();
      if (params.api_id) searchParams.set("api_id", params.api_id);
      if (params.severity) searchParams.set("severity", params.severity);
      if (params.status) searchParams.set("status", params.status);
      const str = searchParams.toString();
      if (str) q = `?${str}`;
    }
    const res = await this.request<ScanFinding[]>(`/vulnerabilities${q}`);
    return res.data;
  }

  static async getVulnerabilityDetail(id: string): Promise<ScanFinding> {
    const res = await this.request<ScanFinding>(`/vulnerabilities/${id}`);
    return res.data;
  }

  static async updateVulnerability(id: string, payload: { status?: string; assignee_id?: string; due_date?: string }) {
    return await this.request(`/vulnerabilities/${id}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    });
  }

  static async addFindingComment(id: string, commentText: string) {
    return await this.request(`/vulnerabilities/${id}/comments`, {
      method: "POST",
      body: JSON.stringify({ comment_text: commentText }),
    });
  }

  // Monitoring
  static async getMonitoringOverview(): Promise<MonitoringOverview[]> {
    const res = await this.request<MonitoringOverview[]>("/monitoring/overview");
    return res.data;
  }

  static async getApiMonitoring(apiId: string): Promise<MonitoringOverview> {
    const res = await this.request<MonitoringOverview>(`/monitoring/apis/${apiId}`);
    return res.data;
  }

  static async triggerHealthCheck(apiId: string) {
    return await this.request(`/monitoring/apis/${apiId}/check`, { method: "POST" });
  }

  static async getAnomalies(apiId?: string): Promise<AnomalyEvent[]> {
    const q = apiId ? `?api_id=${apiId}` : "";
    const res = await this.request<AnomalyEvent[]>(`/monitoring/anomalies${q}`);
    return res.data;
  }

  // Alerts
  static async getAlerts(): Promise<AlertItem[]> {
    const res = await this.request<AlertItem[]>("/alerts");
    return res.data;
  }

  static async updateAlert(id: string, payload: { status?: string; assigned_user_id?: string }) {
    return await this.request(`/alerts/${id}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    });
  }

  // Reports
  static async generateReport(payload: { title: string; scope: string; target_id?: string; report_format: string }): Promise<SecurityReport> {
    const res = await this.request<SecurityReport>("/reports/generate", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    return res.data;
  }

  static async getReports(): Promise<SecurityReport[]> {
    const res = await this.request<SecurityReport[]>("/reports");
    return res.data;
  }

  static async getReportDetail(id: string): Promise<SecurityReport> {
    const res = await this.request<SecurityReport>(`/reports/${id}`);
    return res.data;
  }

  // Audit Logs
  static async getAuditLogs(): Promise<AuditLog[]> {
    const res = await this.request<AuditLog[]>("/audit-logs");
    return res.data;
  }
}
