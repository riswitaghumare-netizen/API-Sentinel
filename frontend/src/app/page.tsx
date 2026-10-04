"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  Server,
  Activity,
  Bug,
  AlertTriangle,
  CheckCircle2,
  TrendingUp,
  ArrowUpRight,
  Radar,
  Play,
  Clock,
  ShieldCheck,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { ApiClient } from "@/lib/api";
import { DashboardStats } from "@/lib/types";

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    ApiClient.getDashboardStats()
      .then((data) => setStats(data))
      .catch((err) => console.error("Failed loading stats:", err))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full min-h-[400px]">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 border-2 border-sky-500 border-t-transparent rounded-full animate-spin"></div>
          <p className="text-xs font-mono text-slate-400">Loading Sentinel Security Analytics...</p>
        </div>
      </div>
    );
  }

  const sevData = [
    { name: "Critical", value: stats?.severity_distribution.critical || 0, color: "#ef4444" },
    { name: "High", value: stats?.severity_distribution.high || 0, color: "#f97316" },
    { name: "Medium", value: stats?.severity_distribution.medium || 0, color: "#eab308" },
    { name: "Low", value: stats?.severity_distribution.low || 0, color: "#3b82f6" },
  ];

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Page Title & Subtitle */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
            <span>SOC Security Operations & Defense Hub</span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              REAL-TIME
            </span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Continuous threat posture, vulnerability metrics, and defensive monitoring for authorized APIs.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Link
            href="/scans"
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 text-white text-xs font-semibold shadow-lg shadow-sky-500/25 transition-all"
          >
            <Radar className="w-4 h-4" />
            <span>Launch Security Scan</span>
          </Link>
        </div>
      </div>

      {/* Top Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Security Score */}
        <div className="p-4 rounded-xl bg-[#0c1222] border border-slate-800/80 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Average Security Score</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white font-mono">
              {stats?.average_security_score ?? 100}
            </span>
            <span className="text-xs text-slate-400 font-mono">/ 100</span>
          </div>
          <div className="mt-2 text-[11px] text-emerald-400 flex items-center gap-1 font-medium">
            <span>Grade: {stats && stats.average_security_score >= 80 ? "Good Posture" : "Needs Review"}</span>
          </div>
        </div>

        {/* Critical Vulnerabilities */}
        <div className="p-4 rounded-xl bg-[#0c1222] border border-slate-800/80 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Critical Threats</span>
            <ShieldAlert className="w-4 h-4 text-rose-500" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-rose-500 font-mono">
              {stats?.critical_vulnerabilities ?? 0}
            </span>
            <span className="text-xs text-slate-400 font-mono">unresolved</span>
          </div>
          <div className="mt-2 text-[11px] text-rose-400 flex items-center gap-1 font-medium">
            <span>Immediate remediation required</span>
          </div>
        </div>

        {/* High Threats */}
        <div className="p-4 rounded-xl bg-[#0c1222] border border-slate-800/80 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">High Risk Findings</span>
            <AlertTriangle className="w-4 h-4 text-amber-500" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-amber-400 font-mono">
              {stats?.high_vulnerabilities ?? 0}
            </span>
            <span className="text-xs text-slate-400 font-mono">open</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400 font-medium">
            <span>Total open findings: {stats?.open_findings ?? 0}</span>
          </div>
        </div>

        {/* Monitored APIs */}
        <div className="p-4 rounded-xl bg-[#0c1222] border border-slate-800/80 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Active API Targets</span>
            <Activity className="w-4 h-4 text-sky-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white font-mono">
              {stats?.monitored_apis ?? 0}
            </span>
            <span className="text-xs text-slate-400 font-mono">/ {stats?.total_apis ?? 0}</span>
          </div>
          <div className="mt-2 text-[11px] text-emerald-400 flex items-center gap-1 font-medium">
            <span>Availability: {stats?.overall_availability ?? 100}%</span>
          </div>
        </div>
      </div>

      {/* Main Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Vulnerability Trends Area Chart */}
        <div className="lg:col-span-2 p-5 rounded-2xl bg-[#0c1222] border border-slate-800/80">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-white">7-Day Vulnerability Trend</h2>
              <p className="text-[11px] text-slate-400">Active security findings progression over time</p>
            </div>
            <div className="flex items-center gap-3 text-[11px] font-mono">
              <span className="flex items-center gap-1.5 text-rose-400">
                <span className="w-2 h-2 rounded-full bg-rose-500"></span> Critical
              </span>
              <span className="flex items-center gap-1.5 text-amber-400">
                <span className="w-2 h-2 rounded-full bg-amber-500"></span> High
              </span>
              <span className="flex items-center gap-1.5 text-sky-400">
                <span className="w-2 h-2 rounded-full bg-sky-500"></span> Medium/Low
              </span>
            </div>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={stats?.vulnerability_trends || []} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="highGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f97316" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#f97316" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: 8, fontSize: 12 }}
                />
                <Area type="monotone" dataKey="critical" stroke="#ef4444" fillOpacity={1} fill="url(#critGrad)" strokeWidth={2} />
                <Area type="monotone" dataKey="high" stroke="#f97316" fillOpacity={1} fill="url(#highGrad)" strokeWidth={2} />
                <Area type="monotone" dataKey="medium" stroke="#eab308" fillOpacity={0} strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Distribution Donut Chart */}
        <div className="p-5 rounded-2xl bg-[#0c1222] border border-slate-800/80 flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-semibold text-white">Severity Distribution</h2>
            <p className="text-[11px] text-slate-400">Current open finding breakdown</p>
          </div>
          <div className="h-44 w-full relative flex items-center justify-center my-2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={sevData}
                  cx="50%"
                  cy="50%"
                  innerRadius={45}
                  outerRadius={65}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {sevData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: 8, fontSize: 12 }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute flex flex-col items-center justify-center pointer-events-none">
              <span className="text-xl font-bold font-mono text-white">{stats?.open_findings ?? 0}</span>
              <span className="text-[10px] text-slate-400 uppercase">Findings</span>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800/80 text-xs">
            {sevData.map((s) => (
              <div key={s.name} className="flex items-center justify-between px-2 py-1 rounded bg-slate-900/60">
                <div className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: s.color }}></span>
                  <span className="text-slate-300 text-[11px]">{s.name}</span>
                </div>
                <span className="font-mono font-bold text-white text-[11px]">{s.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Bottom Row: Top Risks & Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Risks Matrix */}
        <div className="p-5 rounded-2xl bg-[#0c1222] border border-slate-800/80">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h2 className="text-sm font-semibold text-white">Top Risk API Targets</h2>
              <p className="text-[11px] text-slate-400">APIs prioritized by threat severity and exposure</p>
            </div>
            <Link href="/apis" className="text-xs text-sky-400 hover:underline flex items-center gap-1">
              View All <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>
          <div className="space-y-2.5">
            {stats?.top_risks && stats.top_risks.length > 0 ? (
              stats.top_risks.map((api) => (
                <Link
                  key={api.id}
                  href={`/apis/${api.id}`}
                  className="flex items-center justify-between p-3 rounded-xl bg-slate-900/70 border border-slate-800/60 hover:border-slate-700 transition-all block group"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold text-slate-200 group-hover:text-sky-300 transition-colors">
                        {api.name}
                      </span>
                      <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                        {api.environment}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 mt-1 text-[11px] text-slate-400">
                      <span>Crit: <strong className="text-rose-400">{api.critical_count}</strong></span>
                      <span>High: <strong className="text-amber-400">{api.high_count}</strong></span>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-bold font-mono text-white">{api.security_score}/100</div>
                    <span className="text-[10px] text-slate-400">Score</span>
                  </div>
                </Link>
              ))
            ) : (
              <p className="text-xs text-slate-400 py-6 text-center">No high-risk APIs registered yet.</p>
            )}
          </div>
        </div>

        {/* Recent Scans Feed */}
        <div className="p-5 rounded-2xl bg-[#0c1222] border border-slate-800/80">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h2 className="text-sm font-semibold text-white">Recent Security Scans</h2>
              <p className="text-[11px] text-slate-400">Execution log and discovered threat summaries</p>
            </div>
            <Link href="/scans" className="text-xs text-sky-400 hover:underline flex items-center gap-1">
              Scan History <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>
          <div className="space-y-2.5">
            {stats?.recent_scans && stats.recent_scans.length > 0 ? (
              stats.recent_scans.map((scan) => (
                <div
                  key={scan.id}
                  className="flex items-center justify-between p-3 rounded-xl bg-slate-900/70 border border-slate-800/60 text-xs"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-400">
                      <Radar className="w-4 h-4" />
                    </div>
                    <div>
                      <p className="font-semibold text-slate-200">{scan.api_name}</p>
                      <p className="text-[11px] text-slate-400">{scan.profile_name}</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                        scan.status === "COMPLETED"
                          ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                          : scan.status === "RUNNING"
                          ? "bg-sky-500/10 text-sky-400 border border-sky-500/30 animate-pulse"
                          : "bg-rose-500/10 text-rose-400 border border-rose-500/30"
                      }`}
                    >
                      {scan.status}
                    </span>
                    <p className="text-[10px] text-slate-400 mt-1 font-mono">{scan.duration_seconds}s duration</p>
                  </div>
                </div>
              ))
            ) : (
              <p className="text-xs text-slate-400 py-6 text-center">No scans executed yet.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
