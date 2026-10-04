"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ShieldAlert,
  LayoutDashboard,
  Server,
  Radar,
  Bug,
  Activity,
  Bell,
  FileText,
  History,
  Settings,
  Terminal,
} from "lucide-react";

interface NavItem {
  name: string;
  href: string;
  icon: React.ElementType;
  badge?: string;
  badgeColor?: string;
}

const navigation: NavItem[] = [
  { name: "SOC Dashboard", href: "/", icon: LayoutDashboard },
  { name: "API Inventory", href: "/apis", icon: Server },
  { name: "Scan Center", href: "/scans", icon: Radar },
  { name: "Vulnerabilities", href: "/vulnerabilities", icon: Bug },
  { name: "Monitoring & Health", href: "/monitoring", icon: Activity },
  { name: "Security Alerts", href: "/alerts", icon: Bell },
  { name: "Security Reports", href: "/reports", icon: FileText },
  { name: "Audit Logs", href: "/audit-logs", icon: History },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 bg-[#0c1222] border-r border-slate-800/80 flex flex-col shrink-0 select-none">
      {/* Brand Header */}
      <div className="h-16 flex items-center px-5 gap-3 border-b border-slate-800/80 bg-[#090e1a]">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-sky-600 to-cyan-400 flex items-center justify-center shadow-lg shadow-sky-500/20">
          <ShieldAlert className="w-5 h-5 text-white" />
        </div>
        <div>
          <div className="flex items-center gap-1.5">
            <span className="font-bold text-base tracking-tight text-white">API Sentinel</span>
            <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/30">
              v1.0
            </span>
          </div>
          <p className="text-[11px] text-slate-400 font-mono">Defensive SecOps</p>
        </div>
      </div>

      {/* Navigation Links */}
      <div className="flex-1 py-4 px-3 space-y-1 overflow-y-auto">
        <div className="px-3 pb-2 text-[10px] font-mono uppercase tracking-wider text-slate-400">
          Platform Operations
        </div>
        {navigation.map((item) => {
          const isActive = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));
          const Icon = item.icon;

          return (
            <Link
              key={item.name}
              href={item.href}
              className={`flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all group ${
                isActive
                  ? "bg-sky-500/15 text-sky-300 border border-sky-500/30 shadow-sm"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon
                  className={`w-4 h-4 transition-colors ${
                    isActive ? "text-sky-400" : "text-slate-400 group-hover:text-slate-300"
                  }`}
                />
                <span>{item.name}</span>
              </div>
            </Link>
          );
        })}
      </div>

      {/* Engine Status Widget */}
      <div className="p-3 m-3 rounded-xl bg-slate-900/90 border border-slate-800 text-[11px]">
        <div className="flex items-center justify-between mb-1.5">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="font-medium text-slate-300">Scanner Engine</span>
          </div>
          <span className="text-[10px] font-mono text-emerald-400">ONLINE</span>
        </div>
        <div className="text-slate-400 text-[10px] leading-relaxed">
          SSRF Guard: <span className="text-slate-300">Active</span> • RBAC: <span className="text-slate-300">Enforced</span>
        </div>
      </div>
    </aside>
  );
}
