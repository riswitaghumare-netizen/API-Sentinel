"use client";

import React, { useState, useEffect } from "react";
import {
  History,
  Shield,
  Search,
  Filter,
  CheckCircle2,
  RefreshCw,
  Terminal,
} from "lucide-react";
import { ApiClient } from "@/lib/api";
import { AuditLog } from "@/lib/types";

export default function AuditLogsPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);

  const loadLogs = () => {
    setLoading(true);
    ApiClient.getAuditLogs()
      .then((data) => setLogs(data))
      .catch((err) => console.error("Failed loading audit logs:", err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadLogs();
  }, []);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
            <History className="w-6 h-6 text-sky-400" />
            <span>Immutable Security Audit Log</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Complete tamper-resistant timeline of all administrative operations, authentication events, and scan executions.
          </p>
        </div>
        <button
          onClick={loadLogs}
          className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs font-semibold"
        >
          <RefreshCw className="w-3.5 h-3.5" /> Refresh Log
        </button>
      </div>

      {/* Audit Log Table */}
      <div className="rounded-2xl bg-[#0c1222] border border-slate-800/80 overflow-hidden shadow-xl">
        {loading ? (
          <div className="py-16 text-center text-xs font-mono text-slate-400">Loading audit trail...</div>
        ) : logs.length === 0 ? (
          <div className="py-16 text-center text-xs text-slate-400">No audit events recorded yet.</div>
        ) : (
          <div className="divide-y divide-slate-800/60 font-mono text-xs">
            {logs.map((l) => (
              <div key={l.id} className="p-4 hover:bg-slate-900/40 transition-colors flex items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                      l.status === "SUCCESS"
                        ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                        : "bg-rose-500/10 text-rose-400 border border-rose-500/30"
                    }`}
                  >
                    {l.status}
                  </span>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-slate-200">{l.action}</span>
                      <span className="text-slate-500 text-[10px]">[{l.resource_type}]</span>
                    </div>
                    <p className="text-[11px] text-slate-400 font-sans mt-0.5">
                      Actor: <strong className="text-slate-300">{l.user_email || "System"}</strong> • IP: {l.ip_address || "Internal"}
                    </p>
                  </div>
                </div>

                <div className="text-right text-[11px] text-slate-500 shrink-0">
                  {new Date(l.created_at).toLocaleString()}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
