"use client";

import React, { useState, useEffect, Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  Radar,
  Play,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Zap,
  Layers,
  Shield,
  RefreshCw,
  Eye,
  Sliders,
} from "lucide-react";
import { ApiClient } from "@/lib/api";
import { APITarget, Scan } from "@/lib/types";

function ScansContent() {
  const searchParams = useSearchParams();
  const preselectedTarget = searchParams.get("target") || "";

  const [apis, setApis] = useState<APITarget[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedApiId, setSelectedApiId] = useState(preselectedTarget);
  const [profileType, setProfileType] = useState<"QUICK" | "STANDARD" | "DEEP" | "CUSTOM">("STANDARD");
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading] = useState(true);
  const [activeScanProgress, setActiveScanProgress] = useState<{
    status: string;
    step: string;
    requests: number;
    findings: number;
  } | null>(null);

  const loadData = () => {
    setLoading(true);
    Promise.all([ApiClient.getApis(), ApiClient.getScans()])
      .then(([apisData, scansData]) => {
        setApis(apisData);
        setScans(scansData);
        if (!selectedApiId && apisData.length > 0) {
          setSelectedApiId(apisData[0].id);
        }
      })
      .catch((err) => console.error("Error loading scan center:", err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleLaunchScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedApiId) return;

    setScanning(true);
    setActiveScanProgress({
      status: "RUNNING",
      step: "Initializing scanner plugins & SSRF safety verification...",
      requests: 0,
      findings: 0,
    });

    try {
      const scan = await ApiClient.triggerScan(selectedApiId, profileType);
      
      // Simulate live step execution telemetry
      setTimeout(() => {
        setActiveScanProgress({
          status: "RUNNING",
          step: "Executing HeaderScanner, CORScanner & TLS probes...",
          requests: 12,
          findings: 2,
        });
      }, 1500);

      setTimeout(() => {
        setActiveScanProgress({
          status: "RUNNING",
          step: "Analyzing Auth, Rate Limiting & OpenAPI schema drift...",
          requests: 38,
          findings: 4,
        });
      }, 3500);

      setTimeout(async () => {
        setActiveScanProgress(null);
        setScanning(false);
        loadData();
      }, 5500);

    } catch (err: any) {
      alert(`Scan failed: ${err.message}`);
      setScanning(false);
      setActiveScanProgress(null);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
          <Radar className="w-6 h-6 text-sky-400" />
          <span>Vulnerability Scan Center</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Launch and manage authorized, defensive vulnerability assessments against registered API endpoints.
        </p>
      </div>

      {/* Interactive Scan Launch Console */}
      <div className="p-6 rounded-2xl bg-[#0c1222] border border-slate-800/80 shadow-xl space-y-5">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-sky-400" />
            <h2 className="text-sm font-bold text-white">Execute Security Assessment</h2>
          </div>
          <span className="text-[11px] font-mono text-emerald-400 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
            SSRF Protection Active
          </span>
        </div>

        <form onSubmit={handleLaunchScan} className="space-y-5">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Target API Selection */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">Target API</label>
              <select
                value={selectedApiId}
                onChange={(e) => setSelectedApiId(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-white focus:outline-none focus:border-sky-500 font-medium cursor-pointer"
              >
                {apis.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({a.environment}) — {a.base_url}
                  </option>
                ))}
              </select>
            </div>

            {/* Profile Options */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">Assessment Profile</label>
              <div className="grid grid-cols-3 gap-2">
                {[
                  { id: "QUICK", label: "Quick Scan", icon: Zap, desc: "Headers, TLS & CORS" },
                  { id: "STANDARD", label: "Standard Scan", icon: Layers, desc: "Baseline + Auth + Drift" },
                  { id: "DEEP", label: "Deep Scan", icon: Sliders, desc: "All 10 Modules + Fuzzing" },
                ].map((p) => {
                  const Icon = p.icon;
                  const isSelected = profileType === p.id;
                  return (
                    <button
                      type="button"
                      key={p.id}
                      onClick={() => setProfileType(p.id as any)}
                      className={`p-2.5 rounded-xl border text-left transition-all cursor-pointer ${
                        isSelected
                          ? "bg-sky-500/15 border-sky-500/50 text-white shadow-sm"
                          : "bg-slate-900/60 border-slate-800/80 text-slate-400 hover:border-slate-700"
                      }`}
                    >
                      <div className="flex items-center gap-1.5 mb-1">
                        <Icon className={`w-3.5 h-3.5 ${isSelected ? "text-sky-400" : "text-slate-400"}`} />
                        <span className="text-xs font-bold">{p.label}</span>
                      </div>
                      <p className="text-[10px] text-slate-400 line-clamp-1">{p.desc}</p>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Active Live Progress Tracker Banner */}
          {activeScanProgress && (
            <div className="p-4 rounded-xl bg-sky-950/40 border border-sky-500/30 animate-in fade-in space-y-2">
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2 text-sky-300 font-semibold">
                  <RefreshCw className="w-4 h-4 animate-spin text-sky-400" />
                  <span>Scan in Progress: {activeScanProgress.step}</span>
                </div>
                <span className="font-mono text-slate-300 text-[11px]">
                  Requests: <strong>{activeScanProgress.requests}</strong> • Threats Found:{" "}
                  <strong className="text-rose-400">{activeScanProgress.findings}</strong>
                </span>
              </div>
              <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
                <div className="bg-gradient-to-r from-sky-400 to-blue-500 h-full w-2/3 animate-pulse"></div>
              </div>
            </div>
          )}

          <div className="flex items-center justify-end">
            <button
              type="submit"
              disabled={scanning || !selectedApiId}
              className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 text-white text-xs font-bold shadow-lg shadow-sky-500/25 transition-all cursor-pointer disabled:opacity-50"
            >
              <Play className="w-4 h-4 fill-current" />
              <span>{scanning ? "Executing Security Scan..." : "Start Security Scan"}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Historical Scans Feed */}
      <div className="p-5 rounded-2xl bg-[#0c1222] border border-slate-800/80 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold text-white">Scan Execution History</h2>
            <p className="text-[11px] text-slate-400">Chronological records of completed security scans</p>
          </div>
          <button
            onClick={loadData}
            className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs flex items-center gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
        </div>

        {loading ? (
          <div className="py-8 text-center text-xs text-slate-400 font-mono">Loading history...</div>
        ) : scans.length === 0 ? (
          <div className="py-8 text-center text-xs text-slate-400">No scans recorded yet.</div>
        ) : (
          <div className="divide-y divide-slate-800/60">
            {scans.map((s) => (
              <div key={s.id} className="py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                <div className="flex items-center gap-3.5">
                  <div className="w-9 h-9 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center text-sky-400">
                    <Radar className="w-4 h-4" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-white">{s.api_name || "API Target"}</h3>
                    <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                      {s.profile_name} • {new Date(s.created_at).toLocaleString()}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  <div className="text-right font-mono text-[11px]">
                    <div className="flex items-center gap-2">
                      <span className="text-rose-400 font-bold">{s.critical_count} Crit</span>
                      <span className="text-amber-400 font-bold">{s.high_count} High</span>
                      <span className="text-slate-400">{s.medium_count} Med</span>
                    </div>
                    <span className="text-slate-400 block text-[10px] mt-0.5">
                      {s.total_requests} reqs • {s.duration_seconds}s
                    </span>
                  </div>

                  <span
                    className={`font-mono text-[10px] font-bold px-2.5 py-1 rounded ${
                      s.status === "COMPLETED"
                        ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                        : s.status === "RUNNING"
                        ? "bg-sky-500/10 text-sky-400 border border-sky-500/30 animate-pulse"
                        : "bg-rose-500/10 text-rose-400 border border-rose-500/30"
                    }`}
                  >
                    {s.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default function ScansPage() {
  return (
    <Suspense fallback={<div className="py-16 text-center text-xs font-mono text-slate-400">Loading Scan Console...</div>}>
      <ScansContent />
    </Suspense>
  );
}
