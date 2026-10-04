"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import {
  Server,
  ShieldCheck,
  ShieldAlert,
  Activity,
  Play,
  Key,
  Code2,
  Bug,
  Radar,
  ArrowLeft,
  Lock,
  Plus,
  RefreshCw,
  Clock,
  AlertTriangle,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { ApiClient } from "@/lib/api";
import { APIDetail, Scan, ScanFinding, MonitoringOverview } from "@/lib/types";

export default function APIDetailPage() {
  const params = useParams();
  const router = useRouter();
  const apiId = params.id as string;

  const [api, setApi] = useState<APIDetail | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [vulns, setVulns] = useState<ScanFinding[]>([]);
  const [monitoring, setMonitoring] = useState<MonitoringOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<"endpoints" | "vulns" | "monitoring" | "scans" | "credentials">("endpoints");
  const [checking, setChecking] = useState(false);

  const loadData = () => {
    setLoading(true);
    Promise.all([
      ApiClient.getApiDetail(apiId),
      ApiClient.getScans(apiId),
      ApiClient.getVulnerabilities({ api_id: apiId }),
      ApiClient.getApiMonitoring(apiId).catch(() => null),
    ])
      .then(([apiData, scansData, vulnsData, monData]) => {
        setApi(apiData);
        setScans(scansData);
        setVulns(vulnsData);
        setMonitoring(monData);
      })
      .catch((err) => console.error("Failed loading API detail:", err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadData();
  }, [apiId]);

  const handleHealthCheck = async () => {
    setChecking(true);
    try {
      await ApiClient.triggerHealthCheck(apiId);
      loadData();
    } catch (err: any) {
      alert(err.message);
    } finally {
      setChecking(false);
    }
  };

  if (loading || !api) {
    return (
      <div className="py-20 text-center text-xs font-mono text-slate-400 flex flex-col items-center gap-3">
        <div className="w-8 h-8 border-2 border-sky-500 border-t-transparent rounded-full animate-spin"></div>
        <span>Loading API Security Detail Hub...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Back Button & Title Banner */}
      <div className="flex items-center gap-3">
        <Link
          href="/apis"
          className="p-2 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-400 hover:text-white transition-all"
        >
          <ArrowLeft className="w-4 h-4" />
        </Link>
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2.5">
            <span>{api.name}</span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 uppercase">
              {api.environment}
            </span>
          </h1>
          <p className="text-xs font-mono text-slate-400 mt-0.5">{api.base_url}</p>
        </div>
      </div>

      {/* Top Posture Summary Bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Security Score */}
        <div className="p-4 rounded-xl bg-[#0c1222] border border-slate-800/80">
          <span className="text-xs text-slate-400">Security Score</span>
          <div className="text-2xl font-bold text-white font-mono mt-1">{api.security_score}/100</div>
          <span className="text-[10px] text-emerald-400">Calculated Security Baseline</span>
        </div>

        {/* Open Vulnerabilities */}
        <div className="p-4 rounded-xl bg-[#0c1222] border border-slate-800/80">
          <span className="text-xs text-slate-400">Active Vulnerabilities</span>
          <div className="text-2xl font-bold text-rose-400 font-mono mt-1">{api.open_vulnerabilities_count}</div>
          <span className="text-[10px] text-slate-400">
            {api.critical_vulns} Critical • {api.high_vulns} High
          </span>
        </div>

        {/* Health / Uptime */}
        <div className="p-4 rounded-xl bg-[#0c1222] border border-slate-800/80">
          <span className="text-xs text-slate-400">Health & Availability</span>
          <div className="text-2xl font-bold text-white font-mono mt-1">
            {monitoring?.uptime_percentage_24h ?? 100}%
          </div>
          <span className="text-[10px] text-emerald-400">Avg Latency: {monitoring?.avg_latency_ms_24h ?? 120}ms</span>
        </div>

        {/* Quick Launch Scan */}
        <div className="p-4 rounded-xl bg-[#0c1222] border border-slate-800/80 flex flex-col justify-between">
          <span className="text-xs text-slate-400">Actions</span>
          <div className="flex items-center gap-2 mt-2">
            <Link
              href={`/scans?target=${api.id}`}
              className="flex-1 py-1.5 px-3 rounded-lg bg-sky-500 hover:bg-sky-400 text-white text-xs font-semibold text-center flex items-center justify-center gap-1.5 shadow-md shadow-sky-500/20"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Scan Target</span>
            </Link>
            <button
              onClick={handleHealthCheck}
              disabled={checking}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700"
              title="Ping Health"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${checking ? "animate-spin text-sky-400" : ""}`} />
            </button>
          </div>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="flex items-center gap-2 border-b border-slate-800/80 pb-px">
        {[
          { id: "endpoints", label: `Endpoints (${api.endpoints.length})`, icon: Code2 },
          { id: "vulns", label: `Findings (${vulns.length})`, icon: Bug },
          { id: "monitoring", label: "Continuous Telemetry", icon: Activity },
          { id: "scans", label: `Scan History (${scans.length})`, icon: Radar },
          { id: "credentials", label: `Credentials (${api.credentials.length})`, icon: Key },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-all cursor-pointer ${
                isActive
                  ? "border-sky-500 text-sky-400 bg-sky-500/5 font-semibold"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab Content */}
      <div className="pt-2">
        {/* Tab 1: Discovered Endpoints */}
        {activeTab === "endpoints" && (
          <div className="rounded-2xl bg-[#0c1222] border border-slate-800/80 overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-800/80 flex items-center justify-between">
              <div>
                <h3 className="text-xs font-semibold text-white">Discovered API Endpoints & Routes</h3>
                <p className="text-[11px] text-slate-400">Parsed from OpenAPI spec or network discovery</p>
              </div>
            </div>

            {api.endpoints.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-400">
                No endpoints registered. Import an OpenAPI specification to automatically populate paths.
              </div>
            ) : (
              <div className="divide-y divide-slate-800/60">
                {api.endpoints.map((ep) => (
                  <div key={ep.id} className="p-4 hover:bg-slate-900/40 transition-colors flex items-center justify-between text-xs">
                    <div className="flex items-center gap-3">
                      <span
                        className={`font-mono text-[10px] font-bold px-2 py-0.5 rounded w-16 text-center ${
                          ep.method === "GET"
                            ? "bg-sky-500/15 text-sky-400 border border-sky-500/30"
                            : ep.method === "POST"
                            ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                            : ep.method === "DELETE"
                            ? "bg-rose-500/15 text-rose-400 border border-rose-500/30"
                            : "bg-amber-500/15 text-amber-400 border border-amber-500/30"
                        }`}
                      >
                        {ep.method}
                      </span>
                      <div>
                        <span className="font-mono font-medium text-slate-100">{ep.path}</span>
                        {ep.summary && <p className="text-[11px] text-slate-400 mt-0.5">{ep.summary}</p>}
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      {ep.is_authenticated ? (
                        <span className="flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800">
                          <Lock className="w-3 h-3 text-sky-400" />
                          {ep.auth_type}
                        </span>
                      ) : (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900/50 text-slate-500">
                          Public / Anonymous
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Findings */}
        {activeTab === "vulns" && (
          <div className="space-y-3">
            {vulns.length === 0 ? (
              <div className="p-8 rounded-2xl bg-[#0c1222] border border-slate-800/80 text-center text-xs text-slate-400">
                <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto mb-2" />
                No vulnerabilities detected on this API.
              </div>
            ) : (
              vulns.map((v) => (
                <Link
                  key={v.id}
                  href={`/vulnerabilities/${v.id}`}
                  className="p-4 rounded-xl bg-[#0c1222] border border-slate-800/80 hover:border-slate-700 transition-all flex items-center justify-between text-xs group block"
                >
                  <div className="flex items-center gap-3.5">
                    <span
                      className={`font-mono text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                        v.severity === "CRITICAL"
                          ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                          : v.severity === "HIGH"
                          ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                          : "bg-sky-500/20 text-sky-400 border border-sky-500/30"
                      }`}
                    >
                      {v.severity}
                    </span>
                    <div>
                      <h4 className="font-semibold text-slate-200 group-hover:text-sky-300 transition-colors">
                        {v.title}
                      </h4>
                      <p className="text-[11px] font-mono text-slate-400 mt-0.5">
                        {v.http_method} {v.affected_endpoint_path}
                      </p>
                    </div>
                  </div>

                  <div className="text-right">
                    <span className="text-xs font-mono font-bold text-white">Risk {v.risk_score}/10</span>
                    <p className="text-[10px] text-slate-400 font-mono mt-0.5">{v.status}</p>
                  </div>
                </Link>
              ))
            )}
          </div>
        )}

        {/* Tab 3: Continuous Monitoring */}
        {activeTab === "monitoring" && (
          <div className="p-5 rounded-2xl bg-[#0c1222] border border-slate-800/80 space-y-6">
            <div>
              <h3 className="text-xs font-semibold text-white">24-Hour Response Latency Time Series</h3>
              <p className="text-[11px] text-slate-400">Response time measurements and status code distribution</p>
            </div>

            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={monitoring?.metrics || []}>
                  <defs>
                    <linearGradient id="latencyGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <XAxis
                    dataKey="timestamp"
                    stroke="#64748b"
                    fontSize={10}
                    tickFormatter={(val) => new Date(val).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                  />
                  <YAxis stroke="#64748b" fontSize={10} unit="ms" />
                  <Tooltip
                    contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: 8, fontSize: 11 }}
                  />
                  <Area
                    type="monotone"
                    dataKey="response_time_ms"
                    name="Latency (ms)"
                    stroke="#38bdf8"
                    fill="url(#latencyGrad)"
                    strokeWidth={2}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* Tab 4: Scans */}
        {activeTab === "scans" && (
          <div className="space-y-3">
            {scans.length === 0 ? (
              <div className="p-8 rounded-2xl bg-[#0c1222] border border-slate-800/80 text-center text-xs text-slate-400">
                No scans executed against this target yet.
              </div>
            ) : (
              scans.map((s) => (
                <div key={s.id} className="p-4 rounded-xl bg-[#0c1222] border border-slate-800/80 text-xs flex items-center justify-between">
                  <div>
                    <h4 className="font-semibold text-slate-200">{s.profile_name}</h4>
                    <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                      {new Date(s.created_at).toLocaleString()} • {s.total_requests} requests sent
                    </p>
                  </div>
                  <div className="text-right">
                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                      {s.status}
                    </span>
                    <p className="text-[10px] text-slate-400 mt-1 font-mono">{s.duration_seconds}s duration</p>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* Tab 5: Encrypted Credentials */}
        {activeTab === "credentials" && (
          <div className="p-5 rounded-2xl bg-[#0c1222] border border-slate-800/80 space-y-4">
            <div>
              <h3 className="text-xs font-semibold text-white">Stored Authentication Credentials</h3>
              <p className="text-[11px] text-slate-400">
                All secrets are encrypted at rest with AES-GCM and masked across all interface views.
              </p>
            </div>

            <div className="divide-y divide-slate-800/60">
              {api.credentials.map((c) => (
                <div key={c.id} className="py-3 flex items-center justify-between text-xs">
                  <div>
                    <span className="font-semibold text-slate-200">{c.key_name}</span>
                    <p className="text-[11px] font-mono text-slate-400 mt-0.5">
                      Type: {c.auth_type} • Header: {c.header_name || "Authorization"}
                    </p>
                  </div>
                  <div className="font-mono text-slate-400 bg-slate-900 px-3 py-1 rounded border border-slate-800">
                    {c.masked_preview}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
