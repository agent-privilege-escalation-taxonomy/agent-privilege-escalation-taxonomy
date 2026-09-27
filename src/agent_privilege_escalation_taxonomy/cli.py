from __future__ import annotations

import argparse
import json

from agent_privilege_escalation_taxonomy.classifier import (
    agreement_report,
    classify_traces,
    coverage_matrix,
)
from agent_privilege_escalation_taxonomy.data import assert_pinned_dataset, load_traces
from agent_privilege_escalation_taxonomy.policy import evaluate_traces


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate the agent privilege escalation taxonomy")
    parser.add_argument("--split", default="test", choices=("dev", "test", "all"))
    parser.add_argument("--include-rows", action="store_true")
    args = parser.parse_args()
    hashes = assert_pinned_dataset((args.split,))
    traces = load_traces(args.split)
    classes = classify_traces(traces)
    policy = evaluate_traces(traces)
    if not args.include_rows:
        policy.pop("rows", None)
    report = {
        "hashes": hashes,
        "classification_counts": {
            cls: sum(1 for row in classes if row.escalation_class.value == cls)
            for cls in sorted({row.escalation_class.value for row in classes})
        },
        "coverage_matrix": coverage_matrix((args.split,)),
        "agreement": agreement_report(traces),
        "policy": policy,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
