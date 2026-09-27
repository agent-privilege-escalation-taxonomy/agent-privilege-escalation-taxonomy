<p align="center"><img src="docs/assets/icon.svg" width="112" alt=""></p>

# Agent Privilege Escalation Taxonomy

[![continuous integration](https://github.com/agent-privilege-escalation-taxonomy/agent-privilege-escalation-taxonomy/actions/workflows/continuous-integration.yml/badge.svg)](https://github.com/agent-privilege-escalation-taxonomy/agent-privilege-escalation-taxonomy/actions/workflows/continuous-integration.yml)
[![formal model](https://github.com/agent-privilege-escalation-taxonomy/agent-privilege-escalation-taxonomy/actions/workflows/formal-model.yml/badge.svg)](https://github.com/agent-privilege-escalation-taxonomy/agent-privilege-escalation-taxonomy/actions/workflows/formal-model.yml)
[![security checks](https://github.com/agent-privilege-escalation-taxonomy/agent-privilege-escalation-taxonomy/actions/workflows/security-checks.yml/badge.svg)](https://github.com/agent-privilege-escalation-taxonomy/agent-privilege-escalation-taxonomy/actions/workflows/security-checks.yml)

Agent Privilege Escalation Taxonomy is a reproducible public research artifact for classifying privilege escalation in tool-using agents. It provides deterministic decision rules, an independent agreement check, a class-specific deny-by-default reference policy, a formal deny-by-default model, and benchmark measurements over unmodified benchmark dataset version 4.1.

## Core contribution

The taxonomy has ten mutually exclusive classes: benign, tool scope expansion, confused deputy, credential or secret exfiltration, delegation chain abuse, persistence or hijack, model or artifact substitution, multi-agent collusion, indirect prompt injection into tool calls, and parser control confusion. Each class has a privilege boundary, precondition, observable signal, mitigating control, threat-model mapping, adversarial technique mapping, and deterministic decision rule in `src/agent_privilege_escalation_taxonomy/taxonomy.py`.

The reference policy now implements class-specific controls tuned only on the development split: requester privilege checks, taint propagation from untrusted content into tool effects, structural parser validation, capability manifests, session escalation detection, and secret egress data-flow checks.

## Dataset integrity

This repository does not vendor public benchmark traces. It reads sibling traces from `../zero-trust-agent-benchmark/traces` when present, otherwise the benchmark package installed from the public repository. Every split is hashed before use. The test split pin is `d065bab9bed145490579cd7add6a574c6e23c21c0ea4525dc1c14b0fc15acd2b` for `zero-trust-agent-benchmark-dataset-v4.1`.

A separate extension trace set in `data/extension-v1/` covers taxonomy classes absent from the public benchmark. It is reported separately and never mixed into public benchmark metrics.

## Current measured results

| Metric | Value |
|---|---:|
| Test traces classified | 1000 |
| Mutual exclusivity violations | 0 |
| Exhaustiveness violations | 0 |
| Independent rule agreement | 86.5% |
| Cohen kappa | 0.806 |
| Final policy attack block rate | 482/500 = 96.4%, Wilson [94.4%, 97.7%] |
| Final policy false-positive rate | 4/500 = 0.8%, Wilson [0.3%, 2.0%] |
| Secret leaks allowed | 0 |
| Final policy p95 latency per trace | 0.414 milliseconds |
| Extension test attack block rate | 40/40 = 100.0% |
| Extension test false-positive rate | 0/40 = 0.0% |

## Test-split ablation

| Policy version | Block rate | False-positive rate | p95 latency per trace |
|---|---:|---:|---:|
| Version 1 | 351/500 = 70.2%, Wilson [66.0%, 74.0%] | 4/500 = 0.8%, Wilson [0.3%, 2.0%] | 0.329 milliseconds |
| Compound secret data-flow | 407/500 = 81.4%, Wilson [77.8%, 84.6%] | 4/500 = 0.8%, Wilson [0.3%, 2.0%] | 0.545 milliseconds |
| Requester intent and appraisal | 481/500 = 96.2%, Wilson [94.1%, 97.6%] | 4/500 = 0.8%, Wilson [0.3%, 2.0%] | 0.597 milliseconds |
| Final structural controls | 482/500 = 96.4%, Wilson [94.4%, 97.7%] | 4/500 = 0.8%, Wilson [0.3%, 2.0%] | 0.414 milliseconds |

## Quickstart

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -e ".[dev]"
python -m pip install -e ..\zero-trust-agent-benchmark
agent-privilege-escalation-taxonomy --split test
pytest -q
```

To recreate the committed measurements:

```powershell
python bench\run_benchmarks.py
```

The implementation reports measurements as observed. The final policy is substantially stronger than Version 1, but the public benchmark still contains trace-level cases that cannot be blocked with complete certainty without more runtime provenance.
