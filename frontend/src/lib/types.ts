export type Role = "SUPER_ADMIN" | "SECURITY_ADMIN" | "SECURITY_ANALYST" | "DEVELOPER" | "VIEWER";

export type APIEnvironment = "DEVELOPMENT" | "TESTING" | "STAGING" | "PRODUCTION";
export type RiskClassification = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
export type MonitoringStatus = "ENABLED" | "DISABLED" | "PAUSED";
export type HealthStatus = "HEALTHY" | "DEGRADED" | "DOWN" | "UNKNOWN";
export type AuthType = "NONE" | "API_KEY" | "BEARER_TOKEN" | "BASIC_AUTH" | "OAUTH2" | "CUSTOM_HEADER";

export type VulnerabilitySeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
export type VulnerabilityConfidence = "CERTAIN" | "HIGH" | "MEDIUM" | "LOW";
export type VulnerabilityStatus =
  | "NEW"
  | "OPEN"
  | "IN_REVIEW"
  | "CONFIRMED"
  | "FALSE_POSITIVE"
  | "REMEDIATED"
  | "ACCEPTED_RISK"
  | "REOPENED";

export type ScanStatus = "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED";
export type ScanProfileType = "QUICK" | "STANDARD" | "DEEP" | "CUSTOM";

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: Role;
  organization_id?: string;
  is_active: boolean;
  created_at: string;
}

export interface APIEndpoint {
  id: string;
  path: string;
  method: string;
  summary?: string;
  description?: string;
  parameters: Array<{ name: string; in: string; required: boolean; type?: string }>;
  request_body_schema: Record<string, any>;
  responses_schema: Record<string, any>;
  is_authenticated: boolean;
  auth_type: AuthType;
  is_deprecated: boolean;
  tags: string[];
  last_tested_at?: string;
}

export interface APICredential {
  id: string;
  auth_type: AuthType;
  key_name: string;
  header_name?: string;
  masked_preview: string;
  created_at: string;
}

export interface APITarget {
  id: string;
  project_id: string;
  name: string;
  description?: string;
  base_url: string;
  environment: APIEnvironment;
  owner?: string;
  team?: string;
  tags: string[];
  technology?: string;
  version: string;
  monitoring_status: MonitoringStatus;
  risk_classification: RiskClassification;
  security_score: number;
  health_status: HealthStatus;
  endpoints_count: number;
  open_vulnerabilities_count: number;
  last_scanned_at?: string;
  last_monitored_at?: string;
  created_at: string;
}

export interface APIDetail extends APITarget {
  endpoints: APIEndpoint[];
  credentials: APICredential[];
  critical_vulns: number;
  high_vulns: number;
  medium_vulns: number;
  low_vulns: number;
  info_vulns: number;
}

export interface FindingEvidence {
  id: string;
  request_headers: Record<string, any>;
  request_body?: string;
  response_status?: number;
  response_headers: Record<string, any>;
  response_body_snippet?: string;
  redacted_proof?: string;
  curl_command?: string;
}

export interface FindingComment {
  id: string;
  user_id: string;
  user_name?: string;
  comment_text: string;
  created_at: string;
}

export interface ScanFinding {
  id: string;
  scan_id: string;
  api_id: string;
  api_name?: string;
  endpoint_id?: string;
  title: string;
  severity: VulnerabilitySeverity;
  cvss_score: number;
  risk_score: number;
  confidence: VulnerabilityConfidence;
  http_method: string;
  affected_endpoint_path: string;
  parameter_name?: string;
  description: string;
  risk_explanation: string;
  remediation: string;
  references: string[];
  owasp_category?: string;
  cwe_id?: string;
  nist_control?: string;
  status: VulnerabilityStatus;
  scanner_name: string;
  assignee_id?: string;
  assignee_name?: string;
  due_date?: string;
  first_detected_at: string;
  last_detected_at: string;
  created_at: string;
  evidence?: FindingEvidence;
  comments?: FindingComment[];
}

export interface Scan {
  id: string;
  api_id: string;
  api_name?: string;
  profile_type: ScanProfileType;
  profile_name: string;
  status: ScanStatus;
  start_time?: string;
  end_time?: string;
  duration_seconds: number;
  total_requests: number;
  endpoints_tested: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  scanner_modules_executed: string[];
  error_message?: string;
  created_at: string;
  findings?: ScanFinding[];
}

export interface MetricPoint {
  timestamp: string;
  is_available: boolean;
  status_code: number;
  response_time_ms: number;
  headers_intact: boolean;
  tls_valid: boolean;
  error_message?: string;
}

export interface MonitoringOverview {
  api_id: string;
  api_name: string;
  current_status: string;
  uptime_percentage_24h: number;
  avg_latency_ms_24h: number;
  p95_latency_ms_24h: number;
  total_checks_24h: number;
  failed_checks_24h: number;
  last_check_time?: string;
  metrics: MetricPoint[];
}

export interface AnomalyEvent {
  id: string;
  api_id: string;
  api_name?: string;
  anomaly_type: string;
  severity: string;
  baseline_value: number;
  observed_value: number;
  deviation_percent: number;
  details: string;
  timestamp: string;
}

export interface AlertItem {
  id: string;
  api_id: string;
  api_name?: string;
  title: string;
  alert_type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  status: "TRIGGERED" | "ACKNOWLEDGED" | "RESOLVED" | "SUPPRESSED";
  description: string;
  evidence?: string;
  recommended_action?: string;
  assigned_user_id?: string;
  resolved_at?: string;
  created_at: string;
}

export interface DashboardStats {
  total_apis: number;
  monitored_apis: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  open_findings: number;
  average_security_score: number;
  overall_availability: number;
  active_alerts: number;
  severity_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
  vulnerability_trends: Array<{
    date: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
  }>;
  top_risks: Array<{
    id: string;
    name: string;
    environment: string;
    security_score: number;
    critical_count: number;
    high_count: number;
    risk_level: string;
  }>;
  recent_scans: Array<{
    id: string;
    api_name: string;
    profile_name: string;
    status: string;
    duration_seconds: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    created_at: string;
  }>;
}

export interface SecurityReport {
  id: string;
  title: string;
  scope: string;
  target_id?: string;
  report_format: "PDF" | "HTML" | "JSON" | "CSV";
  summary_data: Record<string, any>;
  content_payload?: string;
  created_at: string;
}

export interface AuditLog {
  id: string;
  user_id?: string;
  user_email?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  status: string;
  ip_address?: string;
  details: Record<string, any>;
  created_at: string;
}
