@echo off
echo ===================================================================
echo   API Sentinel - Secure API Vulnerability Monitoring Platform
echo ===================================================================
echo.
echo Starting Sentinel Core Services...
echo.

start "Sentinel Backend (Port 8000)" cmd /k "cd backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"
timeout /t 2 /nobreak >nul

start "Sentinel Demo Target API (Port 8001)" cmd /k "cd demo-api && python app.py"
timeout /t 1 /nobreak >nul

start "Sentinel Web Client (Port 3000)" cmd /k "cd frontend && npm run dev"

echo.
echo [✓] All services launched!
echo.
echo   - SOC Dashboard:   http://localhost:3000
echo   - Backend API:     http://localhost:8000/docs
echo   - Demo Target API: http://localhost:8001/docs
echo.
echo Default Demo Credentials:
echo   - Super Admin:     admin@sentinel.sec / SentinelAdmin2026!
echo   - Security Analyst: analyst@sentinel.sec / AnalystPass2026!
echo   - Developer:       dev@sentinel.sec / DevPass2026!
echo ===================================================================
pause
