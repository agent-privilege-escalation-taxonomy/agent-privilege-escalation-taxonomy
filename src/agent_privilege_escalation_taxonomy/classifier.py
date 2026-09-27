from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from agent_privilege_escalation_taxonomy.data import TraceRecord, iter_steps, load_traces
from agent_privilege_escalation_taxonomy.stats import cohen_kappa
from agent_privilege_escalation_taxonomy.taxonomy import ENTRY_BY_CLASS, EscalationClass

CONTROL_TEXT_RE = re.compile(
    r"<\|(?:end|start|channel|message)\|>|<start_of_turn>|private channel", re.I
)
CREDENTIAL_RE = re.compile(
    r"(?i)(secret://|credential|private token|access key|support secret|opaque credential)"
)
PROMPT_INJECTION_RE = re.compile(
    r"(?i)(ignore previous|override the user|policy changed|bypass|private drop box|outside collection|upload handoff|stop summarizing|share .* externally)"
)
TOOL_SCOPE_RE = re.compile(
    r"(?i)(admin action|privileged operation|degraded posture|missing attestation|unrelated|privileged maintenance|required)"
)
PERSISTENCE_RE = re.compile(
    r"(?i)(startup|scheduled task|tool manifest|policy bundle|autoload|profile\.d)"
)
ARTIFACT_RE = re.compile(r"(?i)(model hash|artifact hash|hash mismatch|publisher|adapter|binary)")
COLLUSION_RE = re.compile(r"(?i)(collusion|handoff chain|shared collector|partial exfiltration)")

FAMILY_RULES: Mapping[str, EscalationClass] = {
    "prompt_injection": EscalationClass.INDIRECT_PROMPT_INJECTION,
    "control_token": EscalationClass.PARSER_CONTROL_CONFUSION,
    "parser_confusion": EscalationClass.PARSER_CONTROL_CONFUSION,
    "tool_hijack": EscalationClass.TOOL_SCOPE_EXPANSION,
    "tool_poisoning": EscalationClass.CONFUSED_DEPUTY,
    "data_exfil": EscalationClass.CREDENTIAL_EXFILTRATION,
    "priv_esc": EscalationClass.TOOL_SCOPE_EXPANSION,
    "delegation_chain_abuse": EscalationClass.DELEGATION_CHAIN_ABUSE,
    "persistence_hijack": EscalationClass.PERSISTENCE_HIJACK,
    "model_artifact_substitution": EscalationClass.MODEL_ARTIFACT_SUBSTITUTION,
    "multi_agent_collusion": EscalationClass.MULTI_AGENT_COLLUSION,
}

CLASS_PRIORITY: tuple[EscalationClass, ...] = (
    EscalationClass.MODEL_ARTIFACT_SUBSTITUTION,
    EscalationClass.PERSISTENCE_HIJACK,
    EscalationClass.MULTI_AGENT_COLLUSION,
    EscalationClass.CREDENTIAL_EXFILTRATION,
    EscalationClass.PARSER_CONTROL_CONFUSION,
    EscalationClass.CONFUSED_DEPUTY,
    EscalationClass.TOOL_SCOPE_EXPANSION,
    EscalationClass.DELEGATION_CHAIN_ABUSE,
    EscalationClass.INDIRECT_PROMPT_INJECTION,
)


@dataclass(frozen=True)
class Classification:
    trace_id: str
    split: str
    label: str
    family: str
    escalation_class: EscalationClass
    rule_set: str
    matched_rules: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        entry = ENTRY_BY_CLASS[self.escalation_class]
        return {
            "trace_id": self.trace_id,
            "split": self.split,
            "label": self.label,
            "family": self.family,
            "class": self.escalation_class.value,
            "rule_set": self.rule_set,
            "matched_rules": list(self.matched_rules),
            "boundary": entry.boundary.value,
            "security_threats": list(entry.security_threats),
            "mitre_artificial_intelligence_techniques": list(
                entry.mitre_artificial_intelligence_techniques
            ),
        }


def _text(trace: TraceRecord) -> str:
    return json.dumps(trace, sort_keys=True, default=str)


def _malicious_steps(trace: TraceRecord) -> list[dict[str, Any]]:
    return [step for step in iter_steps(trace) if bool(step.get("malicious", False))]


def _family_rule(trace: TraceRecord) -> Classification:
    label = str(trace.get("label", ""))
    family = str(trace.get("family", ""))
    if label == "benign" or family.startswith("benign_"):
        cls = EscalationClass.BENIGN
        rules = ("benign label",)
    else:
        cls = FAMILY_RULES.get(family, EscalationClass.TOOL_SCOPE_EXPANSION)
        rules = (f"family:{family}",)
    return Classification(
        trace_id=str(trace.get("trace_id", "")),
        split=str(trace.get("split", "")),
        label=label,
        family=family,
        escalation_class=cls,
        rule_set="family",
        matched_rules=rules,
    )


def signal_matches(trace: TraceRecord) -> dict[EscalationClass, tuple[str, ...]]:
    text = _text(trace)
    steps = _malicious_steps(trace) or list(iter_steps(trace))
    tools = {str(step.get("tool", "")) for step in steps}
    origins = {str(step.get("context", {}).get("origin", "")) for step in steps}
    signals: dict[EscalationClass, list[str]] = defaultdict(list)
    if ARTIFACT_RE.search(text):
        signals[EscalationClass.MODEL_ARTIFACT_SUBSTITUTION].append("artifact signal")
    if PERSISTENCE_RE.search(text):
        signals[EscalationClass.PERSISTENCE_HIJACK].append("persistence signal")
    if COLLUSION_RE.search(text):
        signals[EscalationClass.MULTI_AGENT_COLLUSION].append("collusion signal")
    if trace.get("secrets") or CREDENTIAL_RE.search(text):
        signals[EscalationClass.CREDENTIAL_EXFILTRATION].append("credential signal")
    if CONTROL_TEXT_RE.search(text) or str(trace.get("family")) == "parser_confusion":
        signals[EscalationClass.PARSER_CONTROL_CONFUSION].append("parser signal")
    if any(origin.endswith("_server") for origin in origins) or (
        "tool_output" in origins and CREDENTIAL_RE.search(text)
    ):
        signals[EscalationClass.CONFUSED_DEPUTY].append("tool-origin authority signal")
    if TOOL_SCOPE_RE.search(text) or tools & {
        "shell.exec",
        "fs.delete",
        "secrets.get",
        "iam.grant",
    }:
        signals[EscalationClass.TOOL_SCOPE_EXPANSION].append("tool scope signal")
    if any("@" in json.dumps(step.get("args", {})) for step in steps) and (
        "example.net" in text or "invalid" in text
    ):
        signals[EscalationClass.DELEGATION_CHAIN_ABUSE].append("recipient signal")
    if PROMPT_INJECTION_RE.search(text) or "retrieved_doc" in origins:
        signals[EscalationClass.INDIRECT_PROMPT_INJECTION].append("retrieved instruction signal")
    return {key: tuple(value) for key, value in signals.items()}


def _signal_rule(trace: TraceRecord) -> Classification:
    if str(trace.get("label", "")) == "benign":
        return Classification(
            str(trace.get("trace_id", "")),
            str(trace.get("split", "")),
            str(trace.get("label", "")),
            str(trace.get("family", "")),
            EscalationClass.BENIGN,
            "signal",
            ("benign label",),
        )
    signals = signal_matches(trace)
    for cls in CLASS_PRIORITY:
        if cls in signals:
            matched = signals[cls]
            break
    else:
        cls = EscalationClass.TOOL_SCOPE_EXPANSION
        matched = ("attack fallback",)
    return Classification(
        str(trace.get("trace_id", "")),
        str(trace.get("split", "")),
        str(trace.get("label", "")),
        str(trace.get("family", "")),
        cls,
        "signal",
        matched,
    )


def classify_trace(trace: TraceRecord, rule_set: str = "family") -> Classification:
    if rule_set == "family":
        return _family_rule(trace)
    if rule_set == "signal":
        return _signal_rule(trace)
    raise ValueError(f"unknown rule set: {rule_set}")


def classify_traces(
    traces: Iterable[TraceRecord], rule_set: str = "family"
) -> list[Classification]:
    return [classify_trace(trace, rule_set) for trace in traces]


def class_frequency(rows: Iterable[Classification]) -> dict[str, int]:
    return dict(Counter(row.escalation_class.value for row in rows))


def coverage_matrix(splits: Iterable[str] = ("dev", "test")) -> dict[str, dict[str, int]]:
    matrix: dict[str, dict[str, int]] = {entry.name.value: {} for entry in ENTRY_BY_CLASS.values()}
    for split in splits:
        rows = classify_traces(load_traces(split))
        counts = Counter(row.escalation_class.value for row in rows)
        for cls in matrix:
            matrix[cls][split] = counts.get(cls, 0)
    return matrix


def mutual_exclusivity_violations(traces: Iterable[TraceRecord]) -> list[str]:
    violations: list[str] = []
    for trace in traces:
        chosen = classify_trace(trace, "family")
        if chosen.escalation_class not in ENTRY_BY_CLASS:
            violations.append(chosen.trace_id)
    return violations


def exhaustiveness_violations(traces: Iterable[TraceRecord]) -> list[str]:
    violations: list[str] = []
    for trace in traces:
        try:
            classify_trace(trace, "family")
        except Exception:
            violations.append(str(trace.get("trace_id", "")))
    return violations


def agreement_report(traces: Iterable[TraceRecord]) -> dict[str, Any]:
    trace_list = list(traces)
    left = classify_traces(trace_list, "family")
    right = classify_traces(trace_list, "signal")
    left_labels = [row.escalation_class.value for row in left]
    right_labels = [row.escalation_class.value for row in right]
    agreements = sum(1 for a, b in zip(left_labels, right_labels, strict=True) if a == b)
    return {
        "count": len(trace_list),
        "agreements": agreements,
        "agreement_rate": agreements / len(trace_list) if trace_list else 1.0,
        "cohen_kappa": cohen_kappa(left_labels, right_labels),
    }
