# Dataset Card

This repository does not vendor public benchmark traces. It consumes `zero-trust-agent-benchmark-dataset-v4.1` from the public benchmark package or from the sibling checkout at `../zero-trust-agent-benchmark/traces`.

Splits:

- `dev.jsonl`: 500 traces, used for development and ablation checks.
- `test.jsonl`: 1,000 traces, used for reported measurements.
- `all.jsonl`: 1,500 traces, used only for integrity verification.

The benchmark profile uses the domain `acme.test`. The loader asserts the following SHA-256 values before data are used:

- `all.jsonl`: 698bde6021459ac1a2ddf51f41897b7c79614e20dc906712dcceb6f51ebb7676
- `dev.jsonl`: 4b6fcd37944e7ad85295805e8b73a4507680a87c9a09c5b1201ab43ef02d1e31
- `test.jsonl`: d065bab9bed145490579cd7add6a574c6e23c21c0ea4525dc1c14b0fc15acd2b

Labels and malicious-step flags are used only for scoring after classification or policy decisions are made. They are not used by the reference policy.

A separate extension data set is documented in `docs/extension-dataset-card.md`. It is generated and hashed by this repository, but it is not mixed into benchmark version 4.1 metrics.
