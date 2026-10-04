import type { Metadata } from "next";
import "./globals.css";
import { Shell } from "@/components/layout/Shell";

export const metadata: Metadata = {
  title: "API Sentinel — Secure API Vulnerability Monitoring Platform",
  description: "Enterprise defensive API security monitoring, vulnerability management, and continuous analytics.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#090d16] text-slate-100 font-sans">
        <Shell>{children}</Shell>
      </body>
    </html>
  );
}
