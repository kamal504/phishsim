#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
#  PhishSim — Start Script
#  Starts both the FastAPI backend (port 8000) and
#  the React dev server (port 5173) in parallel.
# ─────────────────────────────────────────────────────────────────
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "🎣 PhishSim — Phishing Simulator"
echo "================================="

# ── Backend ───────────────────────────────────────────────────
echo "▶ Installing Python dependencies…"
cd "$ROOT/backend"
pip install -r requirements.txt --break-system-packages -q

echo "▶ Starting FastAPI backend on http://localhost:8000"
uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!

# ── Frontend ──────────────────────────────────────────────────
echo "▶ Installing Node dependencies…"
cd "$ROOT/frontend"
npm install --silent

echo "▶ Starting React dev server on http://localhost:5173"
npm run dev &
FRONTEND_PID=$!

echo ""
echo "✅ Both servers are running!"
echo "   API:       http://localhost:8000"
echo "   API Docs:  http://localhost:8000/docs"
echo "   Dashboard: http://localhost:5173"
echo ""
echo "Press Ctrl+C to stop both servers."

# Wait and cleanup on exit
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; echo 'Stopped.'" EXIT
wait
