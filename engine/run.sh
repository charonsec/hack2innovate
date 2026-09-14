#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
VENV="$(pwd)/../../.venv"
if [ -f "$VENV/bin/activate" ]; then
  # shellcheck disable=SC1091
  source "$VENV/bin/activate"
fi
echo "→ HexAudit Python engine starting on :3001"
exec uvicorn auditor.api.main:app --host 0.0.0.0 --port 3001 --reload