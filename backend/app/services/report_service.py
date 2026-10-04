import io
import csv
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from app.models.api import APITarget
from app.models.vulnerability import ScanFinding, VulnerabilityStatus
from app.models.report import SecurityReport, ReportFormat, ReportScope


class ReportService:
    @staticmethod
    async def generate_security_report(
        db: AsyncSession,
        title: str,
        scope: ReportScope,
        target_id: Optional[str] = None,
        report_format: ReportFormat = ReportFormat.HTML,
        user_id: Optional[str] = None,
    ) -> SecurityReport:
        """
        Builds a comprehensive security report covering API posture, findings, and compliance.
        """
        # Fetch targets
        if scope == ReportScope.SINGLE_API and target_id:
            stmt = select(APITarget).where(APITarget.id == target_id).options(
                selectinload(APITarget.endpoints),
                selectinload(APITarget.vulnerabilities).selectinload(ScanFinding.evidence),
            )
            res = await db.execute(stmt)
            apis = res.scalars().all()
        else:
            stmt = select(APITarget).options(
                selectinload(APITarget.endpoints),
                selectinload(APITarget.vulnerabilities).selectinload(ScanFinding.evidence),
            )
            res = await db.execute(stmt)
            apis = res.scalars().all()

        total_apis = len(apis)
        total_endpoints = sum(len(a.endpoints) for a in apis)
        all_vulns = [v for a in apis for v in a.vulnerabilities if v.status not in (VulnerabilityStatus.FALSE_POSITIVE, VulnerabilityStatus.REMEDIATED)]
        
        crit_count = sum(1 for v in all_vulns if v.severity.value == "CRITICAL")
        high_count = sum(1 for v in all_vulns if v.severity.value == "HIGH")
        med_count = sum(1 for v in all_vulns if v.severity.value == "MEDIUM")
        low_count = sum(1 for v in all_vulns if v.severity.value == "LOW")
        info_count = sum(1 for v in all_vulns if v.severity.value == "INFORMATIONAL")

        avg_security_score = sum(a.security_score for a in apis) / max(total_apis, 1)

        # OWASP API Top 10 Breakdown
        owasp_mapping: Dict[str, int] = {}
        for v in all_vulns:
            cat = v.owasp_category or "Uncategorized"
            owasp_mapping[cat] = owasp_mapping.get(cat, 0) + 1

        summary_data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_apis_assessed": total_apis,
            "total_endpoints_evaluated": total_endpoints,
            "average_security_score": round(avg_security_score, 1),
            "critical_findings": crit_count,
            "high_findings": high_count,
            "medium_findings": med_count,
            "low_findings": low_count,
            "informational_findings": info_count,
            "total_open_findings": len(all_vulns),
            "owasp_distribution": owasp_mapping,
        }

        # Build format specific payload
        content_payload = ""
        if report_format == ReportFormat.JSON:
            payload_dict = {
                "report_title": title,
                "summary": summary_data,
                "apis": [
                    {
                        "id": a.id,
                        "name": a.name,
                        "base_url": a.base_url,
                        "environment": a.environment.value,
                        "security_score": a.security_score,
                        "endpoints_count": len(a.endpoints),
                        "findings": [
                            {
                                "id": v.id,
                                "title": v.title,
                                "severity": v.severity.value,
                                "risk_score": v.risk_score,
                                "cvss_score": v.cvss_score,
                                "endpoint": v.affected_endpoint_path,
                                "method": v.http_method,
                                "description": v.description,
                                "remediation": v.remediation,
                                "owasp_category": v.owasp_category,
                                "cwe_id": v.cwe_id,
                            }
                            for v in a.vulnerabilities
                        ]
                    }
                    for a in apis
                ]
            }
            content_payload = json.dumps(payload_dict, indent=2)

        elif report_format == ReportFormat.CSV:
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Finding ID", "API Name", "Severity", "Risk Score", "Title", "Method", "Endpoint", "OWASP Category", "CWE", "Remediation"])
            for a in apis:
                for v in a.vulnerabilities:
                    writer.writerow([
                        v.id,
                        a.name,
                        v.severity.value,
                        v.risk_score,
                        v.title,
                        v.http_method,
                        v.affected_endpoint_path,
                        v.owasp_category,
                        v.cwe_id,
                        v.remediation[:150]
                    ])
            content_payload = output.getvalue()

        else:  # HTML / Printable Executive Security Report
            vuln_rows_html = "".join(
                f"""
                <tr style="border-bottom: 1px solid #334155;">
                    <td style="padding: 12px; font-weight: 600; color: {'#ef4444' if v.severity.value=='CRITICAL' else '#f97316' if v.severity.value=='HIGH' else '#eab308'};">{v.severity.value}</td>
                    <td style="padding: 12px; font-weight: 500;">{v.title}</td>
                    <td style="padding: 12px; font-family: monospace; color: #38bdf8;">{v.http_method} {v.affected_endpoint_path}</td>
                    <td style="padding: 12px;">{v.owasp_category or 'N/A'}</td>
                    <td style="padding: 12px; font-weight: bold;">{v.risk_score}/10</td>
                </tr>
                """
                for a in apis for v in a.vulnerabilities
            )

            content_payload = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>{title} — API Sentinel Security Report</title>
                <style>
                    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }}
                    .container {{ max-width: 1000px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 32px; border: 1px solid #334155; }}
                    h1 {{ color: #38bdf8; margin-top: 0; }}
                    .badge {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; }}
                    .card-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 24px 0; }}
                    .card {{ background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 16px; text-align: center; }}
                    .card-value {{ font-size: 28px; font-weight: 700; color: #38bdf8; }}
                    .card-label {{ font-size: 13px; color: #94a3b8; margin-top: 4px; }}
                    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                    th {{ background: #0f172a; padding: 12px; text-align: left; font-size: 13px; color: #94a3b8; border-bottom: 2px solid #334155; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>API Sentinel — Executive Security Report</h1>
                    <p style="color: #94a3b8;"><strong>Report Title:</strong> {title} | <strong>Generated:</strong> {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
                    
                    <div class="card-grid">
                        <div class="card"><div class="card-value">{avg_security_score:.1f}</div><div class="card-label">Security Score (0-100)</div></div>
                        <div class="card"><div class="card-value" style="color: #ef4444;">{crit_count}</div><div class="card-label">Critical Findings</div></div>
                        <div class="card"><div class="card-value" style="color: #f97316;">{high_count}</div><div class="card-label">High Findings</div></div>
                        <div class="card"><div class="card-value">{total_apis}</div><div class="card-label">APIs Evaluated</div></div>
                    </div>

                    <h2>Executive Vulnerability Summary</h2>
                    <table>
                        <thead>
                            <tr><th>Severity</th><th>Vulnerability</th><th>Target Endpoint</th><th>OWASP Category</th><th>Risk</th></tr>
                        </thead>
                        <tbody>
                            {vuln_rows_html if vuln_rows_html else '<tr><td colspan="5" style="padding: 20px; text-align: center; color: #22c55e;">No active vulnerabilities detected across assessed targets.</td></tr>'}
                        </tbody>
                    </table>
                </div>
            </body>
            </html>
            """

        report = SecurityReport(
            title=title,
            scope=scope,
            target_id=target_id,
            report_format=report_format,
            generated_by_user_id=user_id,
            summary_data=summary_data,
            content_payload=content_payload,
            created_at=datetime.now(timezone.utc),
        )
        db.add(report)
        await db.commit()
        await db.refresh(report)

        return report
