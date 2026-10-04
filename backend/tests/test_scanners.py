import pytest
import httpx
from app.scanners.header_scanner import HeaderScanner
from app.scanners.cors_scanner import CORScanner
from app.scanners.tls_scanner import TLSScanner
from app.scanners.ratelimit_scanner import RateLimitScanner
from app.scanners.infodisclosure_scanner import InfoDisclosureScanner
from app.scanners.openapi_scanner import OpenAPIScanner
from app.scanners.auth_scanner import AuthenticationScanner
from app.scanners.security_policy_scanner import SecurityPolicyScanner


@pytest.mark.asyncio
async def test_header_scanner_detects_missing_hsts():
    scanner = HeaderScanner()
    
    # Mock transport that returns headers without HSTS or X-Content-Type-Options
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Type": "application/json", "Server": "nginx/1.18.0"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        findings = await scanner.scan(client, "https://api.example.com", [{"path": "/users", "method": "GET"}])
        assert len(findings) >= 2
        titles = [f.title for f in findings]
        assert any("HSTS" in t for t in titles)
        assert any("X-Content-Type-Options" in t for t in titles)


@pytest.mark.asyncio
async def test_cors_scanner_detects_insecure_reflection():
    scanner = CORScanner()

    def handler(request: httpx.Request) -> httpx.Response:
        origin = request.headers.get("Origin", "*")
        return httpx.Response(
            200,
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            },
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        findings = await scanner.scan(client, "https://api.example.com", [{"path": "/users", "method": "GET"}])
        assert len(findings) >= 1
        assert "CORS" in findings[0].title
        assert findings[0].severity.value == "HIGH"


@pytest.mark.asyncio
async def test_info_disclosure_scanner_detects_stack_trace():
    scanner = InfoDisclosureScanner()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            500,
            text='Traceback (most recent call last):\n  File "server.py", line 42\nZeroDivisionError: division by zero',
            headers={"X-Debug-Trace": "true"},
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        findings = await scanner.scan(client, "http://api.example.com", [{"path": "/crash", "method": "GET"}])
        assert len(findings) >= 1
        assert any("Stack Trace" in f.title or "Debug" in f.title for f in findings)


@pytest.mark.asyncio
async def test_tls_scanner_detects_plaintext_http():
    scanner = TLSScanner()
    async with httpx.AsyncClient() as client:
        findings = await scanner.scan(client, "http://api.example.com", [{"path": "/data", "method": "GET"}])
        assert len(findings) >= 1
        assert "Plaintext HTTP" in findings[0].title
        assert findings[0].severity.value == "HIGH"
