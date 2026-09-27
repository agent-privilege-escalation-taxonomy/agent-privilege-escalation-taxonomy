#!/usr/bin/env bash
set -euo pipefail
python_cmd=(python)
if ! command -v python >/dev/null 2>&1; then
  if command -v py >/dev/null 2>&1; then
    python_cmd=(py -3.12)
  elif command -v py.exe >/dev/null 2>&1; then
    python_cmd=(py.exe -3.12)
  elif command -v python.exe >/dev/null 2>&1; then
    python_cmd=(python.exe)
  else
    echo "python not found" >&2
    exit 127
  fi
fi
"${python_cmd[@]}" -m pip install -q -e ".[dev]"
if [ -d "../zero-trust-agent-benchmark" ]; then
  "${python_cmd[@]}" -m pip install -q -e "../zero-trust-agent-benchmark"
else
  "${python_cmd[@]}" -m pip install -q "zero-trust-agent-benchmark @ git+https://github.com/zero-trust-agent-benchmark/zero-trust-agent-benchmark@v0.1.0"
fi
ruff check .
ruff format --check .
mypy src
pytest -q --cov=agent_privilege_escalation_taxonomy --cov-report=term-missing --cov-fail-under=90
bash scripts/tlc.sh
