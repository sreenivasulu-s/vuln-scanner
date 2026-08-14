#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

BACKEND_PID=""
MCP_PID=""
FRONTEND_PID=""

cleanup() {
    echo
    echo "========== STOPPING VULN-SCANNER =========="

    for pid in "$FRONTEND_PID" "$MCP_PID" "$BACKEND_PID"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done

    sleep 1

    for pid in "$FRONTEND_PID" "$MCP_PID" "$BACKEND_PID"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done

    echo "[OK] All services stopped."
}

trap cleanup INT TERM EXIT

echo "=========================================="
echo "       NAYAK THE HACKER SCANNER"
echo "          ONE-COMMAND STARTUP"
echo "=========================================="

echo "[1/7] Checking Python environment..."
if [[ ! -f "$ROOT/venv/bin/activate" ]]; then
    echo "[ERROR] Python virtual environment not found."
    exit 1
fi
source "$ROOT/venv/bin/activate"

echo "[2/7] Checking Python modules..."
python -m py_compile \
    backend/main.py \
    backend/mcp_server.py \
    backend/automation/planner.py

echo "[3/7] Cleaning stale project processes..."

pkill -f "uvicorn backend.main:app" 2>/dev/null || true
pkill -f "python -m backend.mcp_server" 2>/dev/null || true
pkill -f "vite.*--host 127.0.0.1" 2>/dev/null || true

sleep 1

echo "[4/7] Starting Backend..."

uvicorn backend.main:app \
    --host 127.0.0.1 \
    --port 8000 \
    > /tmp/vuln-scanner-backend.log 2>&1 &

BACKEND_PID=$!

for i in {1..30}; do
    if curl -sf http://127.0.0.1:8000/health >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

if ! curl -sf http://127.0.0.1:8000/health >/dev/null 2>&1; then
    echo "[ERROR] Backend failed."
    cat /tmp/vuln-scanner-backend.log
    exit 1
fi

echo "[OK] Backend running."

echo "[5/7] Starting MCP server..."

python -m backend.mcp_server \
    > /tmp/vuln-scanner-mcp.log 2>&1 &

MCP_PID=$!

sleep 2

if ! kill -0 "$MCP_PID" 2>/dev/null; then
    echo "[ERROR] MCP server failed."
    cat /tmp/vuln-scanner-mcp.log
    exit 1
fi

echo "[OK] MCP running."

echo "[6/7] Starting Frontend..."

if [[ ! -d "$ROOT/frontend/node_modules" ]]; then
    echo "[INFO] Installing frontend dependencies..."
    (
        cd "$ROOT/frontend"
        npm install
    )
fi

(
    cd "$ROOT/frontend"
    npm run dev -- --host 127.0.0.1
) > /tmp/vuln-scanner-frontend.log 2>&1 &

FRONTEND_PID=$!

sleep 3

if ! kill -0 "$FRONTEND_PID" 2>/dev/null; then
    echo "[ERROR] Frontend failed."
    cat /tmp/vuln-scanner-frontend.log
    exit 1
fi

echo "[OK] Frontend running."

echo "[7/7] Final health check..."

BACKEND_STATUS="$(curl -sf http://127.0.0.1:8000/health)"

echo
echo "=========================================="
echo "       VULN-SCANNER IS READY"
echo "=========================================="
echo
echo "Frontend : http://127.0.0.1:5173"
echo "Backend  : http://127.0.0.1:8000"
echo "API Docs : http://127.0.0.1:8000/docs"
echo "MCP      : RUNNING"
echo
echo "Health:"
echo "$BACKEND_STATUS"
echo
echo "Logs:"
echo "  Backend  : /tmp/vuln-scanner-backend.log"
echo "  MCP      : /tmp/vuln-scanner-mcp.log"
echo "  Frontend : /tmp/vuln-scanner-frontend.log"
echo
echo "Press Ctrl+C to stop ALL services."
echo "=========================================="

wait
