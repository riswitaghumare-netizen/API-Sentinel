import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """Canvas that adds page numbers in 'Page X of Y' format and running headers."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        if self._pageNumber == 1:
            return  # Skip cover/first page header
        
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        
        # Header
        self.drawString(54, 750, "API SENTINEL — SYSTEM HANDBOOK & INTERVIEW GUIDE")
        self.drawRightString(612 - 54, 750, "CONFIDENTIAL & PROPRIETARY")
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 744, 612 - 54, 744)
        
        # Footer
        self.line(54, 50, 612 - 54, 50)
        self.setFont("Helvetica", 8)
        self.drawString(54, 38, "Defensive API Security & Vulnerability Monitoring Platform")
        self.drawRightString(612 - 54, 38, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


def generate_pdf(output_path="API_Sentinel_Project_Handbook_and_Interview_Mastery_Guide.pdf"):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    # Custom Palette
    c_primary = colors.HexColor("#0F172A")    # Slate 900
    c_accent = colors.HexColor("#0284C7")     # Sky 600
    c_dark_accent = colors.HexColor("#0369A1")
    c_text = colors.HexColor("#1E293B")       # Slate 800
    c_subtext = colors.HexColor("#475569")    # Slate 600
    c_card_bg = colors.HexColor("#F8FAFC")    # Slate 50
    c_border = colors.HexColor("#E2E8F0")     # Slate 200
    c_critical = colors.HexColor("#BE123C")   # Rose 700
    
    # Typography Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=c_primary,
        alignment=TA_LEFT
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=c_accent,
        alignment=TA_LEFT
    )
    
    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=19,
        textColor=c_primary,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )
    
    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=c_dark_accent,
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=c_text,
        alignment=TA_LEFT,
        spaceAfter=5
    )

    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=body_style,
        leftIndent=12,
        firstLineIndent=-8,
        spaceAfter=3
    )

    qa_q_style = ParagraphStyle(
        'QA_Question',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#0369A1"),
        spaceBefore=6,
        spaceAfter=2,
        keepWithNext=True
    )
    
    qa_a_style = ParagraphStyle(
        'QA_Answer',
        parent=body_style,
        textColor=c_text,
        spaceAfter=6
    )

    story = []

    # Title Banner Block
    story.append(Paragraph("API Sentinel — Project Handbook & Interview Guide", title_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph("Full Architecture, Functionality, Performance Engineering & Interview Q&A", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=c_accent, spaceBefore=2, spaceAfter=12))

    # SECTION 1: SYSTEM OVERVIEW & FUNCTIONALITY
    story.append(Paragraph("1. System Overview & Functionality (How It Works & How To Use)", h1_style))
    story.append(Paragraph(
        "<b>API Sentinel</b> is a comprehensive, defensive API Security, Vulnerability Monitoring, and Continuous Analytics platform designed to safeguard web services and APIs against security weaknesses, misconfigurations, and performance anomalies. The system operates strictly within user-authorized boundaries and incorporates multi-layered defensive guardrails.",
        body_style
    ))
    
    story.append(Paragraph("How the Platform Operates (Workflow):", h2_style))
    story.append(Paragraph("• <b>Step 1 — Target Registration & Discovery:</b> Users register API base URLs or import OpenAPI 3.x/Swagger JSON/YAML schemas. The parser automatically extracts endpoints, HTTP methods, query/path parameters, and authentication requirements.", bullet_style))
    story.append(Paragraph("• <b>Step 2 — Defensive SSRF Pre-Flight Verification:</b> Before sending network requests, the SSRF engine validates URL schemes (HTTP/HTTPS only), resolves DNS, and rigorously blocks loopbacks (127.0.0.0/8), RFC 1918 private subnets, link-local, and cloud metadata IMDS IPs (169.254.169.254).", bullet_style))
    story.append(Paragraph("• <b>Step 3 — Multi-Profile Security Assessment:</b> Users trigger assessments (Quick, Standard, Deep, or Custom) that dispatch 10 modular scanner plugins via asynchronous I/O with concurrency controls.", bullet_style))
    story.append(Paragraph("• <b>Step 4 — Evidence Redaction & Triage:</b> When a vulnerability is found, evidence is collected, cryptographic tokens and auth headers are automatically sanitized, CVSS risk scores are calculated, and findings are stored in the database.", bullet_style))
    story.append(Paragraph("• <b>Step 5 — Continuous Monitoring & Telemetry:</b> Periodic background probes track uptime %, latency percentiles (avg, p95), and evaluate response drift against a 24-hour moving baseline (triggering alerts at >2.5 sigma deviation).", bullet_style))
    story.append(Paragraph("• <b>Step 6 — Executive Reporting:</b> Instant on-demand generation of audit-ready HTML/PDF, structured JSON, and raw CSV reports mapped directly to OWASP API Top 10, CWE, and NIST controls.", bullet_style))

    story.append(Spacer(1, 8))

    # SECTION 2: WHAT OUTPUT IT GIVES
    story.append(Paragraph("2. System Outputs & Deliverables", h1_style))
    story.append(Paragraph(
        "The platform produces rich visual, analytical, and structured data across all operational views:",
        body_style
    ))

    outputs_data = [
        [Paragraph("<b>Output Area</b>", body_style), Paragraph("<b>Key Information & Deliverables Produced</b>", body_style)],
        [
            Paragraph("<b>SOC Cyber Dashboard</b>", body_style),
            Paragraph("Top KPI stat cards (Monitored APIs, Endpoints, Active Vulns, Mean Uptime, Security Posture Score), 7-day vulnerability trend Area chart, Severity distribution Donut chart, Top Risk Targets matrix, and Recent Scans activity feed.", body_style)
        ],
        [
            Paragraph("<b>API Inventory Hub</b>", body_style),
            Paragraph("Categorized API cards with environment badges (Dev, Test, Staging, Prod), security score gauges (0-100), discovered endpoint counts, open vulnerability counts, and quick-action scan launchers.", body_style)
        ],
        [
            Paragraph("<b>API Security Hub</b>", body_style),
            Paragraph("Deep multi-tab view for each target: Discovered Endpoints table, Active Vulnerabilities list, 24h Response Latency Time-Series chart, Historical Scans table, and Masked Credential manager.", body_style)
        ],
        [
            Paragraph("<b>Vulnerability Investigation</b>", body_style),
            Paragraph("Multi-factor Risk Score (0-10), CVSS v3.1 vector, Redacted Technical Evidence trace (headers, payload snippets), copyable cURL reproduction command, actionable remediation code, OWASP/CWE mappings, and collaborative triage comment threads.", body_style)
        ],
        [
            Paragraph("<b>Continuous Telemetry</b>", body_style),
            Paragraph("24-hour response latency percentiles (avg, p95), availability % gauges, and statistical anomaly event logs with percent-deviation tracking.", body_style)
        ],
        [
            Paragraph("<b>Executive Reports</b>", body_style),
            Paragraph("Audit-ready printable HTML/PDF reports, structured JSON exports for SIEM pipelines, and CSV spreadsheets detailing compliance mappings and remediation roadmaps.", body_style)
        ]
    ]

    t_out = Table(outputs_data, colWidths=[130, 374])
    t_out.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
        ('GRID', (0, 0), (-1, -1), 0.5, c_border),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_out)

    story.append(Spacer(1, 10))

    # SECTION 3: TECH STACK TABLE
    story.append(Paragraph("3. Comprehensive Technology Stack", h1_style))
    tech_data = [
        [Paragraph("<b>Layer / Component</b>", body_style), Paragraph("<b>Technologies Used & Technical Rationale</b>", body_style)],
        [
            Paragraph("<b>Frontend Framework</b>", body_style),
            Paragraph("<b>Next.js 14 (App Router) + React 18 + TypeScript:</b> Server and client components, strict type safety, fast page transitions, and responsive layout architecture.", body_style)
        ],
        [
            Paragraph("<b>Styling & Aesthetics</b>", body_style),
            Paragraph("<b>Tailwind CSS + Lucide Icons:</b> Curated dark SOC cybersecurity color palette (#090d16 slate-950, cyan/sky accents, glowing status indicators).", body_style)
        ],
        [
            Paragraph("<b>Data Visualization</b>", body_style),
            Paragraph("<b>Recharts:</b> Responsive SVG Area Charts for 24h latency trends, Radial & Pie charts for severity distributions, and custom tooltip formatting.", body_style)
        ],
        [
            Paragraph("<b>Backend Core API</b>", body_style),
            Paragraph("<b>FastAPI (Python 3.11+ / 3.13):</b> High-performance async ASGI web framework, automatic OpenAPI generation, Pydantic v2 data validation schemas, dependency injection for auth & RBAC.", body_style)
        ],
        [
            Paragraph("<b>Database & ORM</b>", body_style),
            Paragraph("<b>SQLAlchemy 2.0 (Async) + SQLite (aiosqlite) / PostgreSQL (asyncpg):</b> Fully asynchronous non-blocking database queries, connection pooling, and declarative models.", body_style)
        ],
        [
            Paragraph("<b>Security & Cryptography</b>", body_style),
            Paragraph("<b>PyJWT + Passlib (Bcrypt) + Cryptography (AES-GCM / Fernet):</b> Stateless JWT tokens, salted password hashing, credential encryption at rest with PBKDF2 key derivation.", body_style)
        ],
        [
            Paragraph("<b>Network & Scanners</b>", body_style),
            Paragraph("<b>HTTPX (Async Client) + dnspython:</b> Asynchronous non-blocking HTTP probes, pre-flight DNS SSRF resolution, connection pooling, and custom timeouts.", body_style)
        ],
        [
            Paragraph("<b>DevOps & Containers</b>", body_style),
            Paragraph("<b>Docker Compose + Nginx Reverse Proxy + Pytest:</b> Multi-container orchestration (Backend, Frontend, Demo API, PostgreSQL, Redis, Nginx) with automated unit test suites.", body_style)
        ]
    ]

    t_tech = Table(tech_data, colWidths=[130, 374])
    t_tech.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
        ('GRID', (0, 0), (-1, -1), 0.5, c_border),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_tech)

    story.append(Spacer(1, 10))

    # SECTION 4: LATENCY & THROUGHPUT OPTIMIZATION
    story.append(Paragraph("4. How Latency & Throughput Are Optimized", h1_style))
    story.append(Paragraph(
        "API Sentinel achieves enterprise throughput and sub-millisecond database/API overhead through careful engineering decisions:",
        body_style
    ))
    story.append(Paragraph("• <b>1. Fully Asynchronous Event-Driven Architecture (ASGI):</b> Built entirely on Python's <code>asyncio</code> and FastAPI/Uvicorn. Incoming HTTP requests, background scanner tasks, and database queries execute concurrently without blocking the main event loop.", bullet_style))
    story.append(Paragraph("• <b>2. Async Database I/O with Connection Pooling:</b> Uses SQLAlchemy 2.0 async engine with <code>asyncpg</code> (PostgreSQL) and <code>aiosqlite</code>. Reusable connection pools eliminate the latency of establishing new TCP/TLS database handshakes for every transaction.", bullet_style))
    story.append(Paragraph("• <b>3. Concurrent Non-Blocking Scanner Probing:</b> The scanner framework dispatches probes concurrently using <code>asyncio.gather()</code> with bounded <code>asyncio.Semaphore</code> concurrency limits. This completes multi-point security audits across dozens of endpoints in 2–4 seconds instead of minutes.", bullet_style))
    story.append(Paragraph("• <b>4. Persistent HTTP Connection Keep-Alive:</b> Reusable <code>httpx.AsyncClient</code> connection pools reuse TCP/TLS tunnels across scanner probes, reducing round-trip latency by up to 60%.", bullet_style))
    story.append(Paragraph("• <b>5. Client-Side State & Optimistic UI:</b> Next.js 14 utilizes fast client routing, local state caching for telemetry series, and streamlined bundle sizes (shared chunks ~87 kB) for sub-second page loads.", bullet_style))
    story.append(Paragraph("• <b>6. Lightweight Statistical Computation:</b> Baseline calculations and anomaly detection compute rolling means and standard deviations in $O(N)$ memory/time using indexed database timestamps.", bullet_style))

    story.append(Spacer(1, 10))

    # SECTION 5: INTERVIEW PREPARATION & TOP Q&A
    story.append(Paragraph("5. Interview Mastery: How to Explain to an Interviewer", h1_style))
    
    story.append(Paragraph("<b>The 60-Second Elevator Pitch:</b>", h2_style))
    story.append(Paragraph(
        "<i>'I engineered <b>API Sentinel</b>, a full-stack defensive API security monitoring and vulnerability management platform. It combines automated vulnerability scanning across 10 security vectors, continuous latency and uptime telemetry with statistical anomaly detection, and enterprise RBAC. I built the backend in FastAPI using fully asynchronous SQLAlchemy and HTTPX with strict SSRF defense controls and encrypted credential vaults, and the frontend in Next.js 14 and Tailwind CSS with real-time SOC cyber telemetry charts.'</i>",
        body_style
    ))

    story.append(Paragraph("<b>Top Technical Interview Questions & Model Answers:</b>", h2_style))

    qas = [
        (
            "Q1: How do you prevent the scanner from becoming a vector for Server-Side Request Forgery (SSRF)?",
            "We enforce a strict pre-flight SSRF filter before any scanner request is dispatched. The system parses the URL, restricts schemes exclusively to HTTP/HTTPS, resolves the hostname to IPv4/IPv6 addresses via DNS, and blocks loopback addresses (127.0.0.0/8), RFC 1918 private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), link-local addresses (169.254.0.0/16), and cloud metadata IMDS IPs (169.254.169.254, metadata.google.internal). Local testing is only permitted when explicit environment flags are set."
        ),
        (
            "Q2: How is sensitive data (like API tokens and evidence traces) protected across the system?",
            "Credentials stored for authenticated scanning are encrypted at rest using AES-GCM / Fernet symmetric cryptography with keys derived via PBKDF2-HMAC. In the UI and logs, tokens are masked (e.g. sk-live-***xyz). When scanners capture request/response evidence, a regex-based sanitization pipeline automatically redacts Authorization headers, bearer tokens, API keys, and sensitive cookie headers before writing to the database."
        ),
        (
            "Q3: How does your risk scoring and API Security Score algorithm work?",
            "We use a composite scoring model. Individual vulnerabilities are assigned a base score using CVSS v3.1 metrics (Base Severity: Critical=9.5, High=8.0, Med=5.0, Low=2.5) multiplied by confidence ratings (Confirmed=1.0, Firm=0.85, Tentative=0.6) and environment exposure factors (Production=1.2, Staging=1.0, Dev=0.8). The API Security Score is a 0–100 scale computed by deducting weighted vulnerability penalties from a baseline of 100."
        ),
        (
            "Q4: How did you implement statistical anomaly detection without heavy ML infrastructure?",
            "We maintain a rolling 24-hour time-series of response latency and HTTP status codes for each API. The service computes the baseline mean (μ) and standard deviation (σ). If subsequent probe responses deviate by more than 2.5 standard deviations (Z-score > 2.5) or if the 5xx error rate exceeds 40%, the system flags an anomaly event and dispatches deduplicated alerts."
        ),
        (
            "Q5: How does the platform scale under heavy scanning workloads?",
            "The backend runs on an asynchronous ASGI event loop. Background scans run as non-blocking tasks. We use connection pooling in HTTPX and SQLAlchemy with semaphore-based rate limiting to prevent socket exhaustion and protect target APIs from unintentional Denial of Service. In production, Redis and Celery/Arq can be attached to distribute scanner workloads across worker nodes."
        )
    ]

    for q, a in qas:
        story.append(Paragraph(f"<b>{q}</b>", qa_q_style))
        story.append(Paragraph(a, qa_a_style))

    # Build PDF document
    doc.build(story, canvasmaker=NumberedCanvas)
    return output_path

if __name__ == "__main__":
    generate_pdf()
