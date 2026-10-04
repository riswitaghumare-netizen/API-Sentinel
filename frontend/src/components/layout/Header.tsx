"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Bell,
  Shield,
  Search,
  Plus,
  Play,
  User as UserIcon,
  LogOut,
  ChevronDown,
  Building,
  CheckCircle2,
} from "lucide-react";
import { ApiClient } from "@/lib/api";
import { AlertItem, User } from "@/lib/types";

export function Header() {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [showAlertsMenu, setShowAlertsMenu] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);

  useEffect(() => {
    // Load cached user or attempt initial auth
    const cached = localStorage.getItem("sentinel_user");
    if (cached) {
      try {
        setUser(JSON.parse(cached));
      } catch (e) {}
    } else {
      // Auto-authenticate as default analyst for demo convenience
      ApiClient.login("admin@sentinel.sec", "SentinelAdmin2026!")
        .then((data) => setUser(data.user))
        .catch(() => {});
    }

    // Load active alerts
    ApiClient.getAlerts()
      .then((data) => setAlerts(data.filter((a) => a.status === "TRIGGERED")))
      .catch(() => {});
  }, []);

  const handleLogout = () => {
    ApiClient.clearToken();
    setUser(null);
    router.push("/login");
  };

  return (
    <header className="h-16 bg-[#0c1222]/90 backdrop-blur-md border-b border-slate-800/80 px-6 flex items-center justify-between sticky top-0 z-30">
      {/* Search & Project Context */}
      <div className="flex items-center gap-4 flex-1 max-w-xl">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300">
          <Building className="w-3.5 h-3.5 text-sky-400" />
          <span className="font-medium text-white">Sentinel Cyber Defense Corp</span>
          <span className="text-slate-600">/</span>
          <span className="text-slate-400">Payment & Customer Platform</span>
        </div>
      </div>

      {/* Action Controls & User Profile */}
      <div className="flex items-center gap-3">
        {/* Quick Scan CTA */}
        <Link
          href="/scans"
          className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 text-white text-xs font-semibold shadow-md shadow-sky-500/20 transition-all cursor-pointer"
        >
          <Play className="w-3.5 h-3.5 fill-current" />
          <span>Launch Scan</span>
        </Link>

        {/* Register API CTA */}
        <Link
          href="/apis"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-all cursor-pointer"
        >
          <Plus className="w-3.5 h-3.5 text-sky-400" />
          <span>Register API</span>
        </Link>

        {/* Notifications Bell Dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowAlertsMenu(!showAlertsMenu)}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 relative transition-all"
            title="Security Alerts"
          >
            <Bell className="w-4 h-4" />
            {alerts.length > 0 && (
              <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-rose-500 text-white text-[10px] font-bold flex items-center justify-center animate-pulse">
                {alerts.length}
              </span>
            )}
          </button>

          {showAlertsMenu && (
            <div className="absolute right-0 mt-2 w-80 rounded-xl bg-slate-900 border border-slate-800 shadow-2xl p-3 z-50 animate-in fade-in slide-in-from-top-2">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800 mb-2">
                <span className="text-xs font-semibold text-white">Active Alerts ({alerts.length})</span>
                <Link href="/alerts" className="text-[11px] text-sky-400 hover:underline">
                  View All
                </Link>
              </div>
              <div className="space-y-2 max-h-60 overflow-y-auto">
                {alerts.length === 0 ? (
                  <div className="text-xs text-slate-400 py-3 text-center flex items-center justify-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    No active threat alerts
                  </div>
                ) : (
                  alerts.slice(0, 4).map((a) => (
                    <div
                      key={a.id}
                      className="p-2 rounded-lg bg-slate-950/70 border border-slate-800/80 text-xs"
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span
                          className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                            a.severity === "CRITICAL"
                              ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                              : "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                          }`}
                        >
                          {a.severity}
                        </span>
                        <span className="text-[10px] text-slate-400">{new Date(a.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                      </div>
                      <p className="font-medium text-slate-200 line-clamp-1">{a.title}</p>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* User Profile */}
        <div className="relative">
          <button
            onClick={() => setShowUserMenu(!showUserMenu)}
            className="flex items-center gap-2.5 pl-2 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 transition-all text-xs"
          >
            <div className="w-6 h-6 rounded-md bg-gradient-to-tr from-sky-500 to-indigo-500 flex items-center justify-center text-[11px] font-bold text-white">
              {user?.full_name?.charAt(0) || "A"}
            </div>
            <div className="text-left hidden sm:block">
              <p className="font-semibold text-slate-200 leading-none">{user?.full_name || "SecOps Lead"}</p>
              <p className="text-[10px] text-slate-400 font-mono mt-0.5">{user?.role || "SUPER_ADMIN"}</p>
            </div>
            <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
          </button>

          {showUserMenu && (
            <div className="absolute right-0 mt-2 w-48 rounded-xl bg-slate-900 border border-slate-800 shadow-2xl p-1.5 z-50">
              <div className="px-3 py-2 border-b border-slate-800 mb-1">
                <p className="text-xs font-semibold text-white">{user?.full_name}</p>
                <p className="text-[10px] text-slate-400 truncate">{user?.email}</p>
              </div>
              <Link
                href="/audit-logs"
                className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs text-slate-300 hover:bg-slate-800 transition-all"
              >
                <Shield className="w-3.5 h-3.5 text-sky-400" />
                Security Audit
              </Link>
              <button
                onClick={handleLogout}
                className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs text-rose-400 hover:bg-rose-500/10 transition-all mt-1"
              >
                <LogOut className="w-3.5 h-3.5" />
                Sign Out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
