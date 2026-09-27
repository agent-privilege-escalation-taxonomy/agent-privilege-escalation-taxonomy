from __future__ import annotations

import importlib.util

import pytest

from agent_privilege_escalation_taxonomy.classifier import (
    agreement_report,
    classify_trace,
    classify_traces,
    coverage_matrix,
    exhaustiveness_violations,
    mutual_exclusivity_violations,
)
from agent_privilege_escalation_taxonomy.data import (
    DATASET_VERSION,
    PINNED_SHA256,
    assert_pinned_dataset,
    assert_pinned_split,
    load_profile,
    load_traces,
)
from agent_privilege_escalation_taxonomy.taxonomy import EscalationClass

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("zero_trust_agent_benchmark") is None,
    reason="zero-trust-agent-benchmark not installed",
)


def test_dataset_version_string() -> None:
    from zero_trust_agent_benchmark.generator import DATASET_VERSION as BENCHMARK_VERSION

    assert BENCHMARK_VERSION == DATASET_VERSION


@pytest.mark.parametrize("split", ["dev", "test", "all"])
def test_dataset_hash_matches_pin(split: str) -> None:
    assert assert_pinned_split(split) == PINNED_SHA256[split]


def test_pinned_dataset_helper_returns_hashes() -> None:
    assert assert_pinned_dataset(("dev", "test")) == {
        "dev": PINNED_SHA256["dev"],
        "test": PINNED_SHA256["test"],
    }


def test_profile_uses_expected_domain() -> None:
    assert load_profile()["trust_domain"] == "acme.test"


@pytest.mark.parametrize(("split", "expected"), [("dev", 500), ("test", 1000), ("all", 1500)])
def test_split_sizes(split: str, expected: int) -> None:
    assert len(load_traces(split)) == expected


@pytest.mark.parametrize("split", ["dev", "test"])
def test_classification_is_total(split: str) -> None:
    traces = load_traces(split)
    assert len(classify_traces(traces)) == len(traces)
    assert exhaustiveness_violations(traces) == []


@pytest.mark.parametrize("split", ["dev", "test"])
def test_classification_is_mutually_exclusive(split: str) -> None:
    assert mutual_exclusivity_violations(load_traces(split)) == []


@pytest.mark.parametrize("split", ["dev", "test"])
def test_each_trace_gets_one_class(split: str) -> None:
    for trace in load_traces(split):
        classification = classify_trace(trace)
        assert isinstance(classification.escalation_class, EscalationClass)


@pytest.mark.parametrize("split", ["dev", "test"])
def test_attack_traces_are_not_benign(split: str) -> None:
    for trace in load_traces(split):
        if trace["label"] == "attack":
            assert classify_trace(trace).escalation_class != EscalationClass.BENIGN


@pytest.mark.parametrize("split", ["dev", "test"])
def test_benign_traces_are_benign(split: str) -> None:
    for trace in load_traces(split):
        if trace["label"] == "benign":
            assert classify_trace(trace).escalation_class == EscalationClass.BENIGN


def test_coverage_matrix_contains_dev_and_test() -> None:
    matrix = coverage_matrix(("dev", "test"))
    assert matrix[EscalationClass.CREDENTIAL_EXFILTRATION.value]["test"] == 100
    assert matrix[EscalationClass.BENIGN.value]["test"] == 500


def test_independent_rule_agreement_is_substantial() -> None:
    report = agreement_report(load_traces("test"))
    assert report["cohen_kappa"] >= 0.60
    assert report["agreement_rate"] >= 0.70


@pytest.mark.parametrize(
    ("family", "expected"),
    [
        ("prompt_injection", EscalationClass.INDIRECT_PROMPT_INJECTION),
        ("control_token", EscalationClass.PARSER_CONTROL_CONFUSION),
        ("tool_hijack", EscalationClass.TOOL_SCOPE_EXPANSION),
        ("tool_poisoning", EscalationClass.CONFUSED_DEPUTY),
        ("parser_confusion", EscalationClass.PARSER_CONTROL_CONFUSION),
        ("data_exfil", EscalationClass.CREDENTIAL_EXFILTRATION),
        ("priv_esc", EscalationClass.TOOL_SCOPE_EXPANSION),
    ],
)
def test_dataset_family_maps_to_expected_class(family: str, expected: EscalationClass) -> None:
    traces = [trace for trace in load_traces("test") if trace["family"] == family]
    assert traces
    assert {classify_trace(trace).escalation_class for trace in traces} == {expected}


def test_classification_serializes_security_metadata() -> None:
    classification = classify_trace(load_traces("test")[0])
    data = classification.as_dict()
    assert data["class"] == classification.escalation_class.value
    assert data["boundary"]
    assert "security_threats" in data
    assert "mitre_artificial_intelligence_techniques" in data


def test_unknown_split_is_rejected() -> None:
    with pytest.raises(ValueError):
        load_traces("unknown")
