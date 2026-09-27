# Changelog

## 0.1.0 - 2026-09-26

- Initial public research release with taxonomy, benchmark harness, formal model, and reproducibility artifacts.
- Added class-specific policy controls tuned only on the development split: requester authority checks, taint-aware tool gating, structural parser validation, session escalation detection, and secret egress data-flow checks.
- Preserved Version 1 measurements and added a test-split ablation from Version 1 to the final policy.
- Added a separate extension trace set for taxonomy classes absent from the public benchmark, with generator, manifest, and dataset card.
- Added literal and shortcut guard tests plus mutation-style adversarial policy tests.
