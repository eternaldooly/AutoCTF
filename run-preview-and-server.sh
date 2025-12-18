#!/usr/bin/env bash
set -euo pipefail

# Optional: override PORT env to run preview on a different port.
# Default is 4176; HTTPS termination can be handled by a reverse proxy (e.g., Nginx) in front.
PORT="${PORT:-4176}"

cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "${PREVIEW_PID:-}" ]]; then
    kill "$PREVIEW_PID" >/dev/null 2>&1 || true
  fi
  exit "$exit_code"
}

trap cleanup EXIT INT TERM

echo "[AUTOCTF] Starting npm run server..."
npm run server &
SERVER_PID=$!

echo "[AUTOCTF] Starting npm run preview -- --host 0.0.0.0 --port ${PORT}..."
npm run preview -- --host 0.0.0.0 --port "${PORT}" &
PREVIEW_PID=$!

echo "[AUTOCTF] Server PID: ${SERVER_PID}, Preview PID: ${PREVIEW_PID}"
echo "[AUTOCTF] Logs follow (Ctrl+C to stop both)."

wait -n "$SERVER_PID" "$PREVIEW_PID"
