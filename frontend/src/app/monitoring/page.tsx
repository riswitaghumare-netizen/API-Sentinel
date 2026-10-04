"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Clock,
  TrendingDown,
  TrendingUp,
  Zap,
} from "lucide-react";
import { ApiClient } from "@/lib/api";
import { MonitoringOverview, AnomalyEvent } from "@/lib/types";

export default function MonitoringPage() {
  const [monitors, setMonitors] = useState<MonitoringOverview[]>([]);
  const [anomalies, setAnomalies] = useState<AnomalyEvent[]>([]);
  const [loading, setLoading] = useState(true);

  const loadData = () => {
    setLoading(true);
    Promise.all([ApiClient.getMonitoringOverview(), ApiClient.getAnomalies()])
      .then(([monData, anomData]) => {
        setMonitors(monData);
        setAnomalies(anomData);
      })
      .catch((err) => console.error("Failed loading monitoring data:", err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadData();
  }, []);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
            <Activity className="w-6 h-6 text-sky-400" />
            <span>Continuous Monitoring & Anomaly Detection</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Automated periodic availability probes, latency percentiles, and statistical anomaly detection.
          </p>
        </div>
        <button
          onClick={loadData}
          className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs font-semibold"
        >
          <RefreshCw className="w-3.5 h-3.5" /> Refresh Telemetry
        </button>
      </div>

      {/* Monitored APIs Health Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {monitors.map((m) => (
          <div key={m.api_id} className="p-5 rounded-2xl bg-[#0c1222] border border-slate-800/80 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="font-bold text-white text-sm">{m.api_name}</h3>
                <span className="text-[11px] text-slate-400 font-mono">
                  Last check: {m.last_check_time ? new Date(m.last_check_time).toLocaleTimeString() : "Never"}
                </span>
              </div>
              <span
                className={`font-mono text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                  m.current_status === "HEALTHY"
                    ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                    : "bg-rose-500/10 text-rose-400 border border-rose-500/30"
                }`}
              >
                {m.current_status}
              </span>
            </div>

            <div className="grid grid-cols-3 gap-2 text-center text-xs font-mono">
              <div className="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800/60">
                <span className="text-[10px] text-slate-400 block font-sans">24h Uptime</span>
                <span className="text-sm font-bold text-white">{m.uptime_percentage_24h}%</span>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800/60">
                <span className="text-[10px] text-slate-400 block font-sans">Avg Latency</span>
                <span className="text-sm font-bold text-sky-400">{m.avg_latency_ms_24h}ms</span>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800/60">
                <span className="text-[10px] text-slate-400 block font-sans">p95 Latency</span>
                <span className="text-sm font-bold text-amber-400">{m.p95_latency_ms_24h}ms</span>
              </div>
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-slate-800/80">
              <span className="text-[11px] text-slate-400">
                Checks (24h): <strong>{m.total_checks_24h}</strong> ({m.failed_checks_24h} failed)
              </span>
              <Link href={`/apis/${m.api_id}`} className="text-xs text-sky-400 hover:underline">
                View Telemetry →
              </Link>
            </div>
          </div>
        ))}
      </div>

      {/* Anomaly Events Log */}
      <div className="p-5 rounded-2xl bg-[#0c1222] border border-slate-800/80 space-y-3">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-amber-400" />
          <span>Statistically Detected Anomalies</span>
        </h2>
        <p className="text-[11px] text-slate-400">
          Deviations exceeding 2.5 standard deviations from baseline response time or error rate spikes.
        </p>

        {anomalies.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-400">
            <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
            No active anomalies detected across monitoring baselines.
          </div>
        ) : (
          <div className="divide-y divide-slate-800/60">
            {anomalies.map((a) => (
              <div key={a.id} className="py-3 flex items-center justify-between text-xs">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-slate-100">{a.anomaly_type}</span>
                    <span className="text-[10px] font-mono text-amber-400 bg-amber-500/10 px-1.5 py-0.2 rounded border border-amber-500/30">
                      +{a.deviation_percent}% deviation
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1">{a.details}</p>
                </div>
                <span className="text-[11px] font-mono text-slate-500">
                  {new Date(a.timestamp).toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
