# Extension Dataset Card

`agent-privilege-escalation-taxonomy-extension-v1` is a small, synthetic, repository-local trace set for taxonomy classes that are absent from public benchmark dataset version 4.1. It is used only for separate coverage and control validation.

## Purpose

The public benchmark contains no traces for delegation chain abuse, persistence or hijack, model or artifact substitution, or multi-agent collusion. This extension set exercises those four classes with paired benign and attack traces so that class-specific controls can be tested without altering public benchmark denominators.

## Generation

Run:

```powershell
python scripts\generate_extension_dataset.py
```

The generator writes `data/extension-v1/dev.jsonl`, `data/extension-v1/test.jsonl`, `data/extension-v1/profile.json`, and `data/extension-v1/manifest.sha256`.

## Splits

| Split | Traces | Attacks | Benign |
|---|---:|---:|---:|
| development | 40 | 20 | 20 |
| test | 80 | 40 | 40 |

Each attack class has 5 development attacks and 10 test attacks. Each class also has matched benign cases.

## Hashes

| File | SHA-256 |
|---|---|
| dev.jsonl | 2803d0b77fd94978d67588c6fe09517941e7f032916646e03d79a9b7e1b37120 |
| profile.json | 5773444692e9e05b28f537f9db40cc42440e2e5e34f855ea8b7d3b841a4d9e63 |
| test.jsonl | d10ac70ca54392007ede9585c7a17c519aa3c2f4bc1b39d889e19bd11756bd65 |

The loader verifies these hashes before using an extension split.

## Reported results

The final policy blocks 40/40 extension test attacks and causes 0/40 benign false positives. These results are reported separately from public benchmark version 4.1.
