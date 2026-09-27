from __future__ import annotations

import pytest

from agent_privilege_escalation_taxonomy.classifier import classify_trace, signal_matches
from agent_privilege_escalation_taxonomy.taxonomy import ENTRY_BY_CLASS, TAXONOMY, EscalationClass


@pytest.mark.parametrize("entry", TAXONOMY)
def test_taxonomy_entries_have_decision_rules(entry) -> None:  # type: ignore[no-untyped-def]
    assert entry.decision_rule
    assert entry.observable_signal
    assert entry.mitigating_control


@pytest.mark.parametrize("entry", TAXONOMY)
def test_taxonomy_entries_have_security_mapping(entry) -> None:  # type: ignore[no-untyped-def]
    assert entry.security_threats
    assert entry.mitre_artificial_intelligence_techniques


def test_taxonomy_has_unique_classes() -> None:
    assert len({entry.name for entry in TAXONOMY}) == len(TAXONOMY)


def test_taxonomy_entry_index_is_complete() -> None:
    assert set(ENTRY_BY_CLASS) == {entry.name for entry in TAXONOMY}


@pytest.mark.parametrize(
    ("family", "expected"),
    [
        ("prompt_injection", EscalationClass.INDIRECT_PROMPT_INJECTION),
        ("control_token", EscalationClass.PARSER_CONTROL_CONFUSION),
        ("parser_confusion", EscalationClass.PARSER_CONTROL_CONFUSION),
        ("tool_hijack", EscalationClass.TOOL_SCOPE_EXPANSION),
        ("tool_poisoning", EscalationClass.CONFUSED_DEPUTY),
        ("data_exfil", EscalationClass.CREDENTIAL_EXFILTRATION),
        ("priv_esc", EscalationClass.TOOL_SCOPE_EXPANSION),
        ("benign_email", EscalationClass.BENIGN),
    ],
)
def test_family_rule_mapping(family: str, expected: EscalationClass) -> None:
    trace = {
        "trace_id": "x",
        "split": "test",
        "label": "benign" if family.startswith("benign") else "attack",
        "family": family,
        "steps": [],
    }
    assert classify_trace(trace).escalation_class == expected


def test_signal_rule_detects_secret_exfiltration() -> None:
    trace = {
        "trace_id": "x",
        "split": "test",
        "label": "attack",
        "family": "custom",
        "secrets": ["s"],
        "steps": [],
    }
    assert (
        classify_trace(trace, "signal").escalation_class == EscalationClass.CREDENTIAL_EXFILTRATION
    )


def test_signal_rule_detects_parser_confusion() -> None:
    trace = {
        "trace_id": "x",
        "split": "test",
        "label": "attack",
        "family": "custom",
        "steps": [{"context": {"content": "<|end|>"}, "malicious": True}],
    }
    assert (
        classify_trace(trace, "signal").escalation_class == EscalationClass.PARSER_CONTROL_CONFUSION
    )


def test_signal_rule_detects_persistence() -> None:
    trace = {
        "trace_id": "x",
        "split": "test",
        "label": "attack",
        "family": "custom",
        "steps": [{"args": {"path": "startup"}, "malicious": True}],
    }
    assert classify_trace(trace, "signal").escalation_class == EscalationClass.PERSISTENCE_HIJACK


def test_signal_rule_detects_artifact_substitution() -> None:
    trace = {
        "trace_id": "x",
        "split": "test",
        "label": "attack",
        "family": "custom",
        "steps": [{"context": {"content": "model hash mismatch"}, "malicious": True}],
    }
    assert (
        classify_trace(trace, "signal").escalation_class
        == EscalationClass.MODEL_ARTIFACT_SUBSTITUTION
    )


def test_signal_rule_detects_collusion() -> None:
    trace = {
        "trace_id": "x",
        "split": "test",
        "label": "attack",
        "family": "custom",
        "steps": [{"context": {"content": "shared collector collusion"}, "malicious": True}],
    }
    assert classify_trace(trace, "signal").escalation_class == EscalationClass.MULTI_AGENT_COLLUSION


def test_unknown_rule_set_rejected() -> None:
    with pytest.raises(ValueError):
        classify_trace({"trace_id": "x"}, "other")


def test_signal_matches_returns_explanations() -> None:
    trace = {
        "trace_id": "x",
        "label": "attack",
        "steps": [{"context": {"content": "missing attestation"}, "malicious": True}],
    }
    matches = signal_matches(trace)
    assert EscalationClass.TOOL_SCOPE_EXPANSION in matches
