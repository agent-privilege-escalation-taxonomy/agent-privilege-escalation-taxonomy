# Reproducibility Notes

Run commands from the repository root on Python 3.12.

```powershell
python -m pip install -e ".[dev]"
python -m pip install -e ..\zero-trust-agent-benchmark
python bench\run_benchmarks.py
pytest -q --cov=agent_privilege_escalation_taxonomy --cov-report=term-missing
```

If the sibling benchmark checkout is unavailable, install the pinned public package instead:

```powershell
python -m pip install "zero-trust-agent-benchmark @ git+https://github.com/zero-trust-agent-benchmark/zero-trust-agent-benchmark@v0.1.0"
```

The benchmark writes `results/reference-run/summary.json`, `env.json`, `measurements.csv`, one hundred per-trial logs, and manifests. It also writes `results/benchmark-dev/summary.json` and `results/benchmark-test/summary.json` for split-specific reporting.
