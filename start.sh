#!/usr/bin/env bash
#
# TrustLens AI – One-command start (Backend + Frontend)
#
# Usage:  ./start.sh
# Stop:   Ctrl+C

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Config ───────────────────────────────────────────────────────────
BE_PORT=3010
FE_PORT=5173
BE_PID=""
FE_PID=""

# ── Colours ──────────────────────────────────────────────────────────
G="\033[92m" C="\033[96m" Y="\033[93m" R="\033[91m" B="\033[1m" D="\033[0m"

# ── Detect Python ────────────────────────────────────────────────────
if [[ -n "$VIRTUAL_ENV" ]]; then
    PY="$VIRTUAL_ENV/bin/python"
elif [[ -f ".venv/bin/python" ]]; then
    PY=".venv/bin/python"
else
    PY="python3"
fi

# ── Cleanup on Ctrl+C / exit ─────────────────────────────────────────
cleanup() {
    echo ""
    echo -e "${Y}Stopping TrustLens AI…${D}"
    [[ -n "$FE_PID" ]] && kill "$FE_PID" 2>/dev/null && wait "$FE_PID" 2>/dev/null
    [[ -n "$BE_PID" ]] && kill "$BE_PID" 2>/dev/null && wait "$BE_PID" 2>/dev/null
    echo -e "${G}✓ Stopped.${D}"
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# ══════════════════════════════════════════════════════════════════════
echo ""
echo -e "${G}${B}╔══════════════════════════════════════════════════╗${D}"
echo -e "${G}${B}║       🔍  TrustLens AI – Unified Start           ║${D}"
echo -e "${G}${B}╚══════════════════════════════════════════════════╝${D}"
echo -e "  Python: ${C}$PY${D}"

# ══════════════════════════════════════════════════════════════════════
#  0. SETUP WIZARD (interactive)
# ══════════════════════════════════════════════════════════════════════
echo ""
echo -e "${B}── LLM Setup ──────────────────────────────────────${D}"

PYTHONPATH=src "$PY" -c "
import sys
sys.path.insert(0, '.')
from setup_wizard import run_wizard, _write_env, _read_env

config = run_wizard()
if config is None:
    print('\033[91mSetup cancelled.\033[0m')
    sys.exit(1)

if config != 'continue':
    _write_env(config)
    p = config.get('TRUSTLENS_AI_PROVIDER', '?')
else:
    p = _read_env().get('TRUSTLENS_AI_PROVIDER', '?')

print(f'\n\033[92m\033[1m  ✓  LLM: {p.upper()}\033[0m')
"

if [[ $? -ne 0 ]]; then exit 1; fi

# ══════════════════════════════════════════════════════════════════════
#  1. INSTALL DEPENDENCIES
# ══════════════════════════════════════════════════════════════════════
echo ""
echo -e "${B}── Installing Dependencies ────────────────────────${D}"

# Backend deps
echo -e "  ${C}pip install -r requirements.txt${D}"
if ! "$PY" -m pip install -r requirements.txt --quiet 2>&1; then
    echo ""
    echo -e "${R}${B}╔══════════════════════════════════════════════════╗${D}"
    echo -e "${R}${B}║  ✗  Backend dependency install failed!           ║${D}"
    echo -e "${R}${B}╠══════════════════════════════════════════════════╣${D}"
    echo -e "${R}${B}║${D}  Run manually:  ${Y}pip install -r requirements.txt${D}"
    echo -e "${R}${B}║${D}  Then restart:  ${Y}./start.sh${D}"
    echo -e "${R}${B}╚══════════════════════════════════════════════════╝${D}"
    exit 1
fi
echo -e "  ${G}✓ Backend deps OK${D}"

# Frontend deps
echo -e "  ${C}npm install (frontend/)${D}"
if ! (cd frontend && npm install 2>&1); then
    echo ""
    echo -e "${R}${B}╔══════════════════════════════════════════════════╗${D}"
    echo -e "${R}${B}║  ✗  Frontend dependency install failed!          ║${D}"
    echo -e "${R}${B}╠══════════════════════════════════════════════════╣${D}"
    echo -e "${R}${B}║${D}  Run manually:  ${Y}cd frontend && npm install${D}"
    echo -e "${R}${B}║${D}  Then restart:  ${Y}./start.sh${D}"
    echo -e "${R}${B}╚══════════════════════════════════════════════════╝${D}"
    exit 1
fi
echo -e "  ${G}✓ Frontend deps OK${D}"

# ══════════════════════════════════════════════════════════════════════
#  2. BACKEND  (port 3010 — kill previous if busy)
# ══════════════════════════════════════════════════════════════════════

echo ""
echo -e "${B}── Backend ────────────────────────────────────────${D}"

# Kill anything on BE_PORT
lsof -iTCP:$BE_PORT -sTCP:LISTEN -t 2>/dev/null | xargs kill -9 2>/dev/null || true
sleep 1

PYTHONPATH=src TRUSTLENS_WIZARD_DONE=1 \
    "$PY" -m uvicorn trustlens.main:app --host 0.0.0.0 --port $BE_PORT &
BE_PID=$!

echo -ne "  Waiting"
for i in $(seq 1 30); do
    curl -sf "http://localhost:$BE_PORT/health" &>/dev/null && break
    kill -0 "$BE_PID" 2>/dev/null || { echo -e "\n${R}✗ Backend crashed.${D}"; exit 1; }
    echo -n "."; sleep 1
done
echo -e "\n  ${G}✓ Backend → http://localhost:$BE_PORT${D}"

# ══════════════════════════════════════════════════════════════════════
#  3. FRONTEND  (port 5173 — kill previous if busy)
# ══════════════════════════════════════════════════════════════════════
echo ""
echo -e "${B}── Frontend ───────────────────────────────────────${D}"

lsof -iTCP:$FE_PORT -sTCP:LISTEN -t 2>/dev/null | xargs kill -9 2>/dev/null || true
sleep 1

cd frontend && npx vite --host &
FE_PID=$!
cd "$SCRIPT_DIR"
sleep 3

# ══════════════════════════════════════════════════════════════════════
#  READY
# ══════════════════════════════════════════════════════════════════════
echo ""
echo -e "${G}${B}╔══════════════════════════════════════════════════╗${D}"
echo -e "${G}${B}║            🚀  TrustLens AI Running               ║${D}"
echo -e "${G}${B}╠══════════════════════════════════════════════════╣${D}"
echo -e "${G}${B}║${D}  Frontend  → ${C}http://localhost:$FE_PORT${D}"
echo -e "${G}${B}║${D}  Backend   → ${C}http://localhost:$BE_PORT${D}"
echo -e "${G}${B}║${D}  API Docs  → ${C}http://localhost:$BE_PORT/docs${D}"
echo -e "${G}${B}╠══════════════════════════════════════════════════╣${D}"
echo -e "${G}${B}║${D}  Press ${Y}Ctrl+C${D} to stop"
echo -e "${G}${B}╚══════════════════════════════════════════════════╝${D}"
echo ""

wait
