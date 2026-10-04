"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import {
  Bug,
  ShieldAlert,
  ArrowLeft,
  Terminal,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Clock,
  User,
  MessageSquare,
  Send,
  ExternalLink,
  BookOpen,
  Copy,
  Check,
} from "lucide-react";
import { ApiClient } from "@/lib/api";
import { ScanFinding } from "@/lib/types";

export default function VulnerabilityDetailPage() {
  const params = useParams();
  const router = useRouter();
  const vulnId = params.id as string;

  const [finding, setFinding] = useState<ScanFinding | null>(null);
  const [loading, setLoading] = useState(true);
  const [commentText, setCommentText] = useState("");
  const [submittingComment, setSubmittingComment] = useState(false);
  const [updatingStatus, setUpdatingStatus] = useState(false);
  const [copied, setCopied] = useState(false);

  const loadFinding = () => {
    setLoading(true);
    ApiClient.getVulnerabilityDetail(vulnId)
      .then((data) => setFinding(data))
      .catch((err) => console.error("Failed loading vulnerability:", err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadFinding();
  }, [vulnId]);

  const handleStatusChange = async (newStatus: string) => {
    setUpdatingStatus(true);
    try {
      await ApiClient.updateVulnerability(vulnId, { status: newStatus });
      loadFinding();
    } catch (err: any) {
      alert(err.message);
    } finally {
      setUpdatingStatus(false);
    }
  };

  const handleAddComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!commentText.trim()) return;

    setSubmittingComment(true);
    try {
      await ApiClient.addFindingComment(vulnId, commentText);
      setCommentText("");
      loadFinding();
    } catch (err: any) {
      alert(err.message);
    } finally {
      setSubmittingComment(false);
    }
  };

  const handleCopyCurl = (cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (loading || !finding) {
    return (
      <div className="py-20 text-center text-xs font-mono text-slate-400 flex flex-col items-center gap-3">
        <div className="w-8 h-8 border-2 border-sky-500 border-t-transparent rounded-full animate-spin"></div>
        <span>Loading Vulnerability Investigation Report...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Back Button & Title */}
      <div className="flex items-center gap-3">
        <Link
          href="/vulnerabilities"
          className="p-2 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-400 hover:text-white transition-all"
        >
          <ArrowLeft className="w-4 h-4" />
        </Link>
        <div>
          <div className="flex items-center gap-2">
            <span
              className={`font-mono text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                finding.severity === "CRITICAL"
                  ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                  : finding.severity === "HIGH"
                  ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                  : "bg-sky-500/20 text-sky-400 border border-sky-500/30"
              }`}
            >
              {finding.severity}
            </span>
            <span className="text-xs font-mono text-slate-400">Scanner: {finding.scanner_name}</span>
          </div>
          <h1 className="text-xl font-bold text-white tracking-tight mt-1">{finding.title}</h1>
        </div>
      </div>

      {/* Triage & Assessment Banner */}
      <div className="p-5 rounded-2xl bg-[#0c1222] border border-slate-800/80 grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div>
          <span className="text-[11px] text-slate-400 block">Calculated Risk Score</span>
          <span className="text-2xl font-bold font-mono text-white mt-0.5 block">{finding.risk_score}/10</span>
          <span className="text-[10px] text-slate-400 font-mono">CVSS: {finding.cvss_score}</span>
        </div>

        <div>
          <span className="text-[11px] text-slate-400 block">Affected Target & Path</span>
          <span className="text-xs font-mono font-bold text-sky-400 mt-1 block truncate">
            {finding.http_method} {finding.affected_endpoint_path}
          </span>
          <span className="text-[10px] text-slate-400 font-mono">{finding.api_name}</span>
        </div>

        <div>
          <span className="text-[11px] text-slate-400 block">Confidence Level</span>
          <span className="text-xs font-mono font-bold text-emerald-400 mt-1 block uppercase">
            {finding.confidence}
          </span>
          <span className="text-[10px] text-slate-400">First Seen: {new Date(finding.first_detected_at).toLocaleDateString()}</span>
        </div>

        <div>
          <label className="text-[11px] text-slate-400 block mb-1">Triage Status</label>
          <select
            value={finding.status}
            disabled={updatingStatus}
            onChange={(e) => handleStatusChange(e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-white focus:outline-none focus:border-sky-500 font-medium cursor-pointer"
          >
            <option value="OPEN">Open</option>
            <option value="IN_REVIEW">In Review</option>
            <option value="CONFIRMED">Confirmed</option>
            <option value="REMEDIATED">Remediated</option>
            <option value="FALSE_POSITIVE">False Positive</option>
            <option value="ACCEPTED_RISK">Accepted Risk</option>
          </select>
        </div>
      </div>

      {/* Description & Threat Impact */}
      <div className="p-6 rounded-2xl bg-[#0c1222] border border-slate-800/80 space-y-4">
        <div>
          <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5">Executive Summary</h2>
          <p className="text-xs text-slate-200 leading-relaxed">{finding.description}</p>
        </div>

        <div className="pt-3 border-t border-slate-800/80">
          <h2 className="text-xs font-bold uppercase tracking-wider text-rose-400 mb-1.5">Security & Business Impact</h2>
          <p className="text-xs text-slate-300 leading-relaxed">{finding.risk_explanation}</p>
        </div>

        <div className="pt-3 border-t border-slate-800/80 flex flex-wrap items-center gap-3 text-xs font-mono">
          <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-sky-400">
            {finding.owasp_category}
          </span>
          <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-amber-400">
            {finding.cwe_id}
          </span>
          <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-emerald-400">
            {finding.nist_control}
          </span>
        </div>
      </div>

      {/* Redacted Technical Evidence Inspector */}
      {finding.evidence && (
        <div className="p-6 rounded-2xl bg-[#0c1222] border border-slate-800/80 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
                <Terminal className="w-4 h-4 text-sky-400" />
                <span>Technical Evidence & Redacted Proof</span>
              </h2>
              <p className="text-[11px] text-slate-400">Secrets and authorization headers have been automatically masked.</p>
            </div>
            {finding.evidence.curl_command && (
              <button
                onClick={() => handleCopyCurl(finding.evidence!.curl_command!)}
                className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs font-mono transition-all"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? "Copied cURL" : "Copy cURL"}</span>
              </button>
            )}
          </div>

          {finding.evidence.redacted_proof && (
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 leading-relaxed">
              <span className="text-sky-400 font-bold block mb-1">[SENTINEL SCANNER PROOF]</span>
              {finding.evidence.redacted_proof}
            </div>
          )}

          {finding.evidence.response_body_snippet && (
            <div>
              <span className="text-[11px] font-mono text-slate-400 block mb-1">Response Payload Snippet:</span>
              <pre className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-emerald-400 overflow-x-auto">
                {finding.evidence.response_body_snippet}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* Actionable Remediation Guidance */}
      <div className="p-6 rounded-2xl bg-emerald-950/20 border border-emerald-500/30 space-y-2">
        <h2 className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span>Recommended Remediation Actions</span>
        </h2>
        <p className="text-xs text-slate-200 leading-relaxed font-sans">{finding.remediation}</p>
      </div>

      {/* Analyst Comments & Collaboration Thread */}
      <div className="p-6 rounded-2xl bg-[#0c1222] border border-slate-800/80 space-y-4">
        <h2 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
          <MessageSquare className="w-4 h-4 text-sky-400" />
          <span>Security Investigation Thread & Comments</span>
        </h2>

        {/* Existing Comments */}
        <div className="space-y-3">
          {finding.comments && finding.comments.length > 0 ? (
            finding.comments.map((c) => (
              <div key={c.id} className="p-3 rounded-xl bg-slate-950 border border-slate-800/80 text-xs">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-semibold text-sky-400">{c.user_name}</span>
                  <span className="text-[10px] text-slate-400">{new Date(c.created_at).toLocaleString()}</span>
                </div>
                <p className="text-slate-200 leading-relaxed">{c.comment_text}</p>
              </div>
            ))
          ) : (
            <p className="text-xs text-slate-400 py-2">No triage notes added yet.</p>
          )}
        </div>

        {/* Add Comment Form */}
        <form onSubmit={handleAddComment} className="flex items-center gap-2 pt-2">
          <input
            type="text"
            required
            placeholder="Add analyst note or remediation update..."
            value={commentText}
            onChange={(e) => setCommentText(e.target.value)}
            className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-slate-100 focus:outline-none focus:border-sky-500"
          />
          <button
            type="submit"
            disabled={submittingComment}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-sky-500 hover:bg-sky-400 text-white text-xs font-bold transition-all shadow-md shadow-sky-500/20"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Post</span>
          </button>
        </form>
      </div>
    </div>
  );
}
