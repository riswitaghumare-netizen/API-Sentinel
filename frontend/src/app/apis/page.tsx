"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  Server,
  Plus,
  Upload,
  Search,
  Filter,
  ShieldCheck,
  ShieldAlert,
  Activity,
  Play,
  Trash2,
  ExternalLink,
  Code2,
} from "lucide-react";
import { ApiClient } from "@/lib/api";
import { APITarget } from "@/lib/types";

export default function APIsPage() {
  const [apis, setApis] = useState<APITarget[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [selectedEnv, setSelectedEnv] = useState<string>("");
  
  // Modals
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  const [creating, setCreating] = useState(false);

  // Form State
  const [newName, setNewName] = useState("");
  const [newBaseUrl, setNewBaseUrl] = useState("http://localhost:8001");
  const [newEnv, setNewEnv] = useState("DEVELOPMENT");
  const [newDesc, setNewDesc] = useState("");
  const [specContent, setSpecContent] = useState("");
  const [formError, setFormError] = useState("");

  const loadApis = () => {
    setLoading(true);
    ApiClient.getApis({ search, environment: selectedEnv || undefined })
      .then((data) => setApis(data))
      .catch((err) => console.error("Failed loading APIs:", err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadApis();
  }, [selectedEnv]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadApis();
  };

  const handleCreateApi = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setFormError("");
    try {
      await ApiClient.createApi({
        name: newName,
        base_url: newBaseUrl,
        environment: newEnv,
        description: newDesc,
      });
      setShowCreateModal(false);
      setNewName("");
      loadApis();
    } catch (err: any) {
      setFormError(err.message || "Failed to create API target.");
    } finally {
      setCreating(false);
    }
  };

  const handleImportSpec = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setFormError("");
    try {
      await ApiClient.importOpenAPI(specContent);
      setShowImportModal(false);
      setSpecContent("");
      loadApis();
    } catch (err: any) {
      setFormError(err.message || "Failed to parse specification.");
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (id: string, name: string) => {
    if (confirm(`Are you sure you want to delete API target '${name}'?`)) {
      try {
        await ApiClient.deleteApi(id);
        loadApis();
      } catch (err: any) {
        alert(err.message);
      }
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
            <Server className="w-6 h-6 text-sky-400" />
            <span>API Inventory & Discovery</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Registered authorized targets, discovered endpoints, and security posture monitoring.
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setShowImportModal(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-all cursor-pointer"
          >
            <Upload className="w-3.5 h-3.5 text-sky-400" />
            <span>Import OpenAPI</span>
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 text-white text-xs font-semibold shadow-md shadow-sky-500/20 transition-all cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Register API</span>
          </button>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="p-4 rounded-xl bg-[#0c1222] border border-slate-800/80 flex flex-col sm:flex-row items-center justify-between gap-3">
        <form onSubmit={handleSearchSubmit} className="relative flex-1 w-full max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search APIs by name or base URL..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500"
          />
        </form>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <span className="text-xs text-slate-400 flex items-center gap-1">
            <Filter className="w-3.5 h-3.5" /> Environment:
          </span>
          <select
            value={selectedEnv}
            onChange={(e) => setSelectedEnv(e.target.value)}
            className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500 cursor-pointer"
          >
            <option value="">All Environments</option>
            <option value="DEVELOPMENT">Development</option>
            <option value="TESTING">Testing</option>
            <option value="STAGING">Staging</option>
            <option value="PRODUCTION">Production</option>
          </select>
        </div>
      </div>

      {/* API Inventory Grid */}
      {loading ? (
        <div className="py-16 text-center text-xs font-mono text-slate-400">Loading APIs...</div>
      ) : apis.length === 0 ? (
        <div className="p-12 rounded-2xl bg-[#0c1222] border border-slate-800/80 text-center">
          <Server className="w-12 h-12 text-slate-600 mx-auto mb-3" />
          <h3 className="text-sm font-semibold text-white">No API targets found</h3>
          <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
            Register your first authorized API endpoint or import an OpenAPI 3.x specification to start monitoring.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {apis.map((api) => (
            <div
              key={api.id}
              className="p-5 rounded-2xl bg-[#0c1222] border border-slate-800/80 hover:border-slate-700 transition-all flex flex-col justify-between group"
            >
              <div>
                {/* Card Top: Badges & Actions */}
                <div className="flex items-center justify-between mb-2">
                  <span
                    className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase ${
                      api.environment === "PRODUCTION"
                        ? "bg-rose-500/15 text-rose-400 border border-rose-500/30"
                        : api.environment === "STAGING"
                        ? "bg-amber-500/15 text-amber-400 border border-amber-500/30"
                        : "bg-sky-500/15 text-sky-400 border border-sky-500/30"
                    }`}
                  >
                    {api.environment}
                  </span>
                  <div className="flex items-center gap-1.5">
                    <button
                      onClick={() => handleDelete(api.id, api.name)}
                      className="p-1 rounded text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                      title="Delete API"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                {/* API Name & Description */}
                <Link href={`/apis/${api.id}`} className="block">
                  <h3 className="text-sm font-bold text-white group-hover:text-sky-400 transition-colors line-clamp-1">
                    {api.name}
                  </h3>
                  <p className="text-xs font-mono text-slate-400 truncate mt-1">{api.base_url}</p>
                  <p className="text-xs text-slate-400 line-clamp-2 mt-2 leading-relaxed">
                    {api.description || "No description provided."}
                  </p>
                </Link>
              </div>

              {/* Card Bottom: Scores & Metrics */}
              <div className="pt-4 mt-4 border-t border-slate-800/80">
                <div className="grid grid-cols-3 gap-2 text-center mb-3">
                  <div className="p-2 rounded-lg bg-slate-900/80">
                    <span className="text-[10px] text-slate-400 block">Endpoints</span>
                    <span className="text-xs font-mono font-bold text-white">{api.endpoints_count}</span>
                  </div>
                  <div className="p-2 rounded-lg bg-slate-900/80">
                    <span className="text-[10px] text-slate-400 block">Open Vulns</span>
                    <span
                      className={`text-xs font-mono font-bold ${
                        api.open_vulnerabilities_count > 0 ? "text-rose-400" : "text-emerald-400"
                      }`}
                    >
                      {api.open_vulnerabilities_count}
                    </span>
                  </div>
                  <div className="p-2 rounded-lg bg-slate-900/80">
                    <span className="text-[10px] text-slate-400 block">Score</span>
                    <span className="text-xs font-mono font-bold text-sky-400">{api.security_score}</span>
                  </div>
                </div>

                <div className="flex items-center justify-between gap-2">
                  <Link
                    href={`/apis/${api.id}`}
                    className="flex-1 py-1.5 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium text-center transition-colors"
                  >
                    View Hub
                  </Link>
                  <Link
                    href={`/scans?target=${api.id}`}
                    className="flex items-center justify-center gap-1.5 py-1.5 px-3 rounded-lg bg-sky-500/20 hover:bg-sky-500/30 text-sky-300 text-xs font-semibold border border-sky-500/30 transition-colors"
                  >
                    <Play className="w-3 h-3 fill-current" /> Scan
                  </Link>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Register API Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-lg rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl p-6">
            <h2 className="text-base font-bold text-white mb-1">Register Authorized API Target</h2>
            <p className="text-xs text-slate-400 mb-4">
              All targets are verified by the internal SSRF protection guardrails prior to scanning.
            </p>

            {formError && (
              <div className="p-3 mb-4 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs">
                {formError}
              </div>
            )}

            <form onSubmit={handleCreateApi} className="space-y-3.5 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">API Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Payments Gateway V2"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-sky-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Base URL</label>
                <input
                  type="url"
                  required
                  placeholder="http://localhost:8001 or https://api.example.com"
                  value={newBaseUrl}
                  onChange={(e) => setNewBaseUrl(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-100 font-mono focus:outline-none focus:border-sky-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Environment</label>
                <select
                  value={newEnv}
                  onChange={(e) => setNewEnv(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-sky-500"
                >
                  <option value="DEVELOPMENT">Development</option>
                  <option value="TESTING">Testing</option>
                  <option value="STAGING">Staging</option>
                  <option value="PRODUCTION">Production</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Description</label>
                <textarea
                  rows={2}
                  placeholder="Brief description of service scope and architecture..."
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-sky-500"
                />
              </div>

              <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="px-4 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 text-white font-semibold shadow-md shadow-sky-500/25"
                >
                  {creating ? "Registering..." : "Register API"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Import OpenAPI Spec Modal */}
      {showImportModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-xl rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl p-6">
            <h2 className="text-base font-bold text-white mb-1">Import OpenAPI / Swagger Specification</h2>
            <p className="text-xs text-slate-400 mb-4">
              Paste JSON or YAML specification to automatically discover paths, methods, parameters, and auth schemes.
            </p>

            {formError && (
              <div className="p-3 mb-4 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs">
                {formError}
              </div>
            )}

            <form onSubmit={handleImportSpec} className="space-y-3.5 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Specification Content (JSON or YAML)</label>
                <textarea
                  rows={8}
                  required
                  placeholder={`{\n  "openapi": "3.0.0",\n  "info": { "title": "My API", "version": "1.0" },\n  "paths": { ... }\n}`}
                  value={specContent}
                  onChange={(e) => setSpecContent(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-slate-100 font-mono text-[11px] focus:outline-none focus:border-sky-500 leading-relaxed"
                />
              </div>

              <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowImportModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="px-4 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 text-white font-semibold shadow-md shadow-sky-500/25"
                >
                  {creating ? "Importing..." : "Parse & Import Spec"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
