"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  Bug,
  Filter,
  Search,
  ShieldAlert,
  ArrowUpRight,
  UserCheck,
  Calendar,
  Layers,
} from "lucide-react";
import { ApiClient } from "@/lib/api";
import { ScanFinding } from "@/lib/types";

export default function VulnerabilitiesPage() {
  const [findings, setFindings] = useState<ScanFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedSeverity, setSelectedSeverity] = useState<string>("");
  const [selectedStatus, setSelectedStatus] = useState<string>("");

  const loadFindings = () => {
    setLoading(true);
    ApiClient.getVulnerabilities({
      severity: selectedSeverity || undefined,
      status: selectedStatus || undefined,
    })
      .then((data) => setFindings(data))
      .catch((err) => console.error("Failed loading findings:", err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadFindings();
  }, [selectedSeverity, selectedStatus]);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
          <Bug className="w-6 h-6 text-rose-400" />
          <span>Vulnerability Management & Triage Hub</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Investigate detected security weaknesses, inspect redacted evidence proofs, and manage remediation status.
        </p>
      </div>

      {/* Filter Bar */}
      <div className="p-4 rounded-xl bg-[#0c1222] border border-slate-800/80 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-400 flex items-center gap-1.5 font-medium">
            <Filter className="w-3.5 h-3.5" /> Severity:
          </span>
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500 cursor-pointer"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFORMATIONAL">Informational</option>
          </select>

          <span className="text-xs text-slate-400 flex items-center gap-1.5 font-medium ml-2">
            Status:
          </span>
          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500 cursor-pointer"
          >
            <option value="">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="IN_REVIEW">In Review</option>
            <option value="CONFIRMED">Confirmed</option>
            <option value="REMEDIATED">Remediated</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>
        </div>

        <span className="text-xs font-mono text-slate-400">
          Showing <strong>{findings.length}</strong> findings
        </span>
      </div>

      {/* Findings Table */}
      <div className="rounded-2xl bg-[#0c1222] border border-slate-800/80 overflow-hidden shadow-xl">
        {loading ? (
          <div className="py-16 text-center text-xs font-mono text-slate-400">Loading findings...</div>
        ) : findings.length === 0 ? (
          <div className="py-16 text-center text-xs text-slate-400">
            No vulnerability findings matching current criteria.
          </div>
        ) : (
          <div className="divide-y divide-slate-800/60">
            {findings.map((f) => (
              <Link
                key={f.id}
                href={`/vulnerabilities/${f.id}`}
                className="p-4 hover:bg-slate-900/40 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs block group"
              >
                <div className="flex items-start gap-3.5">
                  <span
                    className={`font-mono text-[10px] font-bold px-2 py-0.5 rounded uppercase shrink-0 mt-0.5 ${
                      f.severity === "CRITICAL"
                        ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                        : f.severity === "HIGH"
                        ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                        : "bg-sky-500/20 text-sky-400 border border-sky-500/30"
                    }`}
                  >
                    {f.severity}
                  </span>
                  <div>
                    <h3 className="font-semibold text-slate-100 group-hover:text-sky-300 transition-colors">
                      {f.title}
                    </h3>
                    <div className="flex flex-wrap items-center gap-2.5 mt-1 text-[11px] text-slate-400 font-mono">
                      <span className="text-sky-400">
                        {f.http_method} {f.affected_endpoint_path}
                      </span>
                      <span>•</span>
                      <span>Target: {f.api_name || "API Target"}</span>
                      <span>•</span>
                      <span>{f.owasp_category || "API Security"}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-4 sm:shrink-0">
                  <div className="text-right">
                    <span className="text-xs font-mono font-bold text-white block">Risk {f.risk_score}/10</span>
                    <span
                      className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded uppercase mt-0.5 inline-block ${
                        f.status === "OPEN"
                          ? "text-amber-400 bg-amber-500/10 border border-amber-500/20"
                          : f.status === "REMEDIATED"
                          ? "text-emerald-400 bg-emerald-500/10 border border-emerald-500/20"
                          : "text-slate-400 bg-slate-800"
                      }`}
                    >
                      {f.status}
                    </span>
                  </div>
                  <ArrowUpRight className="w-4 h-4 text-slate-600 group-hover:text-slate-300 transition-colors" />
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
