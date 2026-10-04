"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { ShieldAlert, Lock, Mail, User, Building, ArrowRight } from "lucide-react";
import { ApiClient } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState("admin@sentinel.sec");
  const [password, setPassword] = useState("SentinelAdmin2026!");
  const [fullName, setFullName] = useState("");
  const [orgName, setOrgName] = useState("Sentinel Cyber Defense Corp");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      if (isRegister) {
        await ApiClient.register({
          email,
          password,
          full_name: fullName,
          organization_name: orgName,
        });
      } else {
        await ApiClient.login(email, password);
      }
      router.push("/");
    } catch (err: any) {
      setError(err.message || "Authentication failed.");
    } finally {
      setLoading(false);
    }
  };

  const handleQuickFill = (roleEmail: string, rolePass: string) => {
    setEmail(roleEmail);
    setPassword(rolePass);
    setIsRegister(false);
  };

  return (
    <div className="min-h-screen bg-[#090d16] flex items-center justify-center p-4">
      <div className="w-full max-w-md space-y-6">
        {/* Brand Banner */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-2xl bg-gradient-to-tr from-sky-600 to-cyan-400 shadow-xl shadow-sky-500/25 mb-1">
            <ShieldAlert className="w-6 h-6 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">API Sentinel</h1>
          <p className="text-xs text-slate-400">Secure API Vulnerability Monitoring & Security Platform</p>
        </div>

        {/* Auth Card */}
        <div className="p-6 rounded-2xl bg-[#0c1222] border border-slate-800/80 shadow-2xl space-y-5">
          {/* Tab Switcher */}
          <div className="grid grid-cols-2 p-1 rounded-xl bg-slate-900 border border-slate-800 text-xs font-semibold">
            <button
              onClick={() => setIsRegister(false)}
              className={`py-1.5 rounded-lg transition-all ${
                !isRegister ? "bg-sky-500 text-white shadow-sm" : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Sign In
            </button>
            <button
              onClick={() => setIsRegister(true)}
              className={`py-1.5 rounded-lg transition-all ${
                isRegister ? "bg-sky-500 text-white shadow-sm" : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Register
            </button>
          </div>

          {error && (
            <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-3.5 text-xs">
            {isRegister && (
              <>
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Full Name</label>
                  <div className="relative">
                    <User className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                    <input
                      type="text"
                      required
                      placeholder="Alex Mercer"
                      value={fullName}
                      onChange={(e) => setFullName(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-slate-100 focus:outline-none focus:border-sky-500"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">Organization Name</label>
                  <div className="relative">
                    <Building className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                    <input
                      type="text"
                      required
                      placeholder="FinTech Corp"
                      value={orgName}
                      onChange={(e) => setOrgName(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-slate-100 focus:outline-none focus:border-sky-500"
                    />
                  </div>
                </div>
              </>
            )}

            <div>
              <label className="block text-slate-300 font-medium mb-1">Email Address</label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                <input
                  type="email"
                  required
                  placeholder="analyst@sentinel.sec"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-slate-100 focus:outline-none focus:border-sky-500"
                />
              </div>
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">Password</label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                <input
                  type="password"
                  required
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-slate-100 focus:outline-none focus:border-sky-500"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-xl bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 text-white font-bold shadow-lg shadow-sky-500/25 transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
            >
              <span>{loading ? "Authenticating..." : isRegister ? "Create Account" : "Access Platform"}</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </form>

          {/* Quick Fill Demo Roles */}
          <div className="pt-4 border-t border-slate-800/80">
            <span className="text-[10px] text-slate-400 uppercase font-mono block mb-2 text-center">
              Quick Demonstration Accounts
            </span>
            <div className="grid grid-cols-3 gap-1.5 text-[11px] font-mono">
              <button
                type="button"
                onClick={() => handleQuickFill("admin@sentinel.sec", "SentinelAdmin2026!")}
                className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-sky-500/50 text-slate-300 text-center transition-all"
              >
                SuperAdmin
              </button>
              <button
                type="button"
                onClick={() => handleQuickFill("analyst@sentinel.sec", "AnalystPass2026!")}
                className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-sky-500/50 text-slate-300 text-center transition-all"
              >
                Analyst
              </button>
              <button
                type="button"
                onClick={() => handleQuickFill("dev@sentinel.sec", "DevPass2026!")}
                className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-sky-500/50 text-slate-300 text-center transition-all"
              >
                Developer
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
