#!/usr/bin/env bash
echo "==================================================================="
echo "  API Sentinel - Secure API Vulnerability Monitoring Platform"
echo "==================================================================="
echo ""
echo "Starting Sentinel Core Services in background..."

# Backend
(cd backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload) &
BACKEND_PID=$!

# Demo API
(cd demo-api && python app.py) &
DEMO_PID=$!

# Frontend
(cd frontend && npm run dev) &
FRONTEND_PID=$!

echo "[✓] Core platform running!"
echo "  - Web Dashboard:   http://localhost:3000"
echo "  - Backend Swagger: http://localhost:8000/docs"
echo "  - Demo API Docs:   http://localhost:8001/docs"
echo ""
echo "Press Ctrl+C to terminate all services."

trap "kill $BACKEND_PID $DEMO_PID $FRONTEND_PID" EXIT
wait
