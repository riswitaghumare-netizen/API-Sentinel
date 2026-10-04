"use client";

import React, { useState, useEffect } from "react";
import {
  Bell,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  Send,
  Plus,
  RefreshCw,
  Clock,
} from "lucide-react";
import { ApiClient } from "@/lib/api";
import { AlertItem } from "@/lib/types";

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [showChannelModal, setShowChannelModal] = useState(false);
  const [channelName, setChannelName] = useState("");
  const [channelUrl, setChannelUrl] = useState("");

  const loadAlerts = () => {
    setLoading(true);
    ApiClient.getAlerts()
      .then((data) => setAlerts(data))
      .catch((err) => console.error("Failed loading alerts:", err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadAlerts();
  }, []);

  const handleResolveAlert = async (id: string) => {
    try {
      await ApiClient.updateAlert(id, { status: "RESOLVED" });
      loadAlerts();
    } catch (err: any) {
      alert(err.message);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
            <Bell className="w-6 h-6 text-amber-400" />
            <span>Security Alerts & Incident Management</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Automated threat detection alerts, deduplication triggers, and SIEM/Webhook dispatchers.
          </p>
        </div>
        <button
          onClick={loadAlerts}
          className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs font-semibold"
        >
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {/* Alerts Feed */}
      <div className="rounded-2xl bg-[#0c1222] border border-slate-800/80 overflow-hidden shadow-xl">
        {loading ? (
          <div className="py-16 text-center text-xs font-mono text-slate-400">Loading security alerts...</div>
        ) : alerts.length === 0 ? (
          <div className="py-16 text-center text-xs text-slate-400 flex flex-col items-center gap-2">
            <CheckCircle2 className="w-10 h-10 text-emerald-400" />
            <p>No active security threat alerts at this time.</p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800/60">
            {alerts.map((a) => (
              <div key={a.id} className="p-4 hover:bg-slate-900/40 transition-colors flex items-start justify-between gap-4 text-xs">
                <div className="flex items-start gap-3.5">
                  <span
                    className={`font-mono text-[10px] font-bold px-2 py-0.5 rounded uppercase shrink-0 mt-0.5 ${
                      a.severity === "CRITICAL"
                        ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                        : "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                    }`}
                  >
                    {a.severity}
                  </span>
                  <div>
                    <h3 className="font-bold text-slate-100">{a.title}</h3>
                    <p className="text-slate-300 mt-1 leading-relaxed">{a.description}</p>
                    {a.recommended_action && (
                      <p className="text-[11px] text-emerald-400 mt-1 font-mono">
                        Action: {a.recommended_action}
                      </p>
                    )}
                    <span className="text-[10px] text-slate-500 font-mono block mt-1.5">
                      Target: {a.api_name || "API Target"} • {new Date(a.created_at).toLocaleString()}
                    </span>
                  </div>
                </div>

                <div className="shrink-0 flex items-center gap-2">
                  {a.status === "TRIGGERED" ? (
                    <button
                      onClick={() => handleResolveAlert(a.id)}
                      className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs border border-slate-700 transition-colors"
                    >
                      Acknowledge & Resolve
                    </button>
                  ) : (
                    <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-1 rounded border border-emerald-500/20">
                      RESOLVED
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
