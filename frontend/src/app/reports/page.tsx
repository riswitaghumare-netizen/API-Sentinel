"use client";

import React, { useState, useEffect } from "react";
import {
  FileText,
  Download,
  Plus,
  RefreshCw,
  Eye,
  CheckCircle2,
  Calendar,
  Layers,
} from "lucide-react";
import { ApiClient } from "@/lib/api";
import { SecurityReport } from "@/lib/types";

export default function ReportsPage() {
  const [reports, setReports] = useState<SecurityReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [title, setTitle] = useState("Executive API Security & Compliance Assessment");
  const [reportFormat, setReportFormat] = useState("HTML");
  const [previewHtml, setPreviewHtml] = useState<string | null>(null);

  const loadReports = () => {
    setLoading(true);
    ApiClient.getReports()
      .then((data) => setReports(data))
      .catch((err) => console.error("Failed loading reports:", err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadReports();
  }, []);

  const handleGenerateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    setGenerating(true);
    try {
      const rep = await ApiClient.generateReport({
        title,
        scope: "ALL_APIS",
        report_format: reportFormat,
      });
      if (rep.content_payload && reportFormat === "HTML") {
        setPreviewHtml(rep.content_payload);
      }
      loadReports();
    } catch (err: any) {
      alert(err.message);
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
          <FileText className="w-6 h-6 text-sky-400" />
          <span>Executive Security & Compliance Reports</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Generate comprehensive audit documentation, OWASP API Top 10 compliance summaries, and remediation roadmaps.
        </p>
      </div>

      {/* Generator Console */}
      <div className="p-6 rounded-2xl bg-[#0c1222] border border-slate-800/80 shadow-xl space-y-4">
        <h2 className="text-sm font-bold text-white">Generate On-Demand Assessment Report</h2>
        
        <form onSubmit={handleGenerateReport} className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
          <div className="sm:col-span-2">
            <label className="block text-slate-300 font-medium mb-1">Report Title</label>
            <input
              type="text"
              required
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-sky-500"
            />
          </div>

          <div>
            <label className="block text-slate-300 font-medium mb-1">Export Format</label>
            <div className="flex gap-2">
              <select
                value={reportFormat}
                onChange={(e) => setReportFormat(e.target.value)}
                className="flex-1 bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-sky-500 cursor-pointer"
              >
                <option value="HTML">HTML / PDF-Ready</option>
                <option value="JSON">Structured JSON</option>
                <option value="CSV">Raw CSV</option>
              </select>
              <button
                type="submit"
                disabled={generating}
                className="px-4 py-2 rounded-xl bg-sky-500 hover:bg-sky-400 text-white font-bold shrink-0 shadow-md shadow-sky-500/20"
              >
                {generating ? "Building..." : "Generate"}
              </button>
            </div>
          </div>
        </form>
      </div>

      {/* HTML Report Live Preview Modal */}
      {previewHtml && (
        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-sky-400">Live Report Preview</h3>
            <button
              onClick={() => setPreviewHtml(null)}
              className="px-3 py-1 rounded bg-slate-800 text-xs text-slate-300 hover:bg-slate-700"
            >
              Close Preview
            </button>
          </div>
          <div className="rounded-xl overflow-hidden border border-slate-800 bg-slate-950 p-2">
            <iframe
              srcDoc={previewHtml}
              className="w-full h-96 rounded bg-slate-900"
              title="Report Preview"
            />
          </div>
        </div>
      )}

      {/* Historical Generated Reports */}
      <div className="p-5 rounded-2xl bg-[#0c1222] border border-slate-800/80 space-y-4">
        <h2 className="text-sm font-bold text-white">Generated Report Library</h2>

        {loading ? (
          <div className="py-8 text-center text-xs text-slate-400 font-mono">Loading report library...</div>
        ) : reports.length === 0 ? (
          <div className="py-8 text-center text-xs text-slate-400">No reports generated yet.</div>
        ) : (
          <div className="divide-y divide-slate-800/60">
            {reports.map((r) => (
              <div key={r.id} className="py-3 flex items-center justify-between text-xs">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-400">
                    <FileText className="w-4 h-4" />
                  </div>
                  <div>
                    <span className="font-semibold text-white">{r.title}</span>
                    <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                      Scope: {r.scope} • Generated: {new Date(r.created_at).toLocaleString()}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] font-bold px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800">
                    {r.report_format}
                  </span>
                  <a
                    href={`http://localhost:8000/api/v1/reports/${r.id}/download`}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" /> Download
                  </a>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
