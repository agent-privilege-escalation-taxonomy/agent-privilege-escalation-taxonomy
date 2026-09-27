from __future__ import annotations

import pytest

from agent_privilege_escalation_taxonomy.classifier import class_frequency, classify_traces
from agent_privilege_escalation_taxonomy.data import (
    EXTENSION_VERSION,
    assert_extension_split,
    benchmark_available,
    extension_manifest,
    load_extension_profile,
    load_extension_traces,
)
from agent_privilege_escalation_taxonomy.policy import evaluate_traces
from agent_privilege_escalation_taxonomy.taxonomy import EscalationClass


def test_extension_version_is_separate_from_public_benchmark() -> None:
    assert EXTENSION_VERSION == "agent-privilege-escalation-taxonomy-extension-v1"


def test_benchmark_package_is_available_for_integration() -> None:
    assert benchmark_available()


def test_unknown_extension_split_is_rejected() -> None:
    with pytest.raises(ValueError):
        assert_extension_split("unknown")


def test_extension_profile_contains_expected_tools() -> None:
    profile = load_extension_profile()
    assert sorted(profile["tools"]) == ["email.send", "fs.write", "http.post", "model.load"]


def test_extension_manifest_records_all_files() -> None:
    manifest = extension_manifest()
    assert set(manifest) == {"dev.jsonl", "profile.json", "test.jsonl"}
    assert assert_extension_split("dev") == manifest["dev.jsonl"]
    assert assert_extension_split("test") == manifest["test.jsonl"]


def test_extension_split_sizes_and_balance() -> None:
    assert len(load_extension_traces("dev")) == 40
    assert len(load_extension_traces("test")) == 80
    assert sum(trace["label"] == "attack" for trace in load_extension_traces("test")) == 40
    assert sum(trace["label"] == "benign" for trace in load_extension_traces("test")) == 40


def test_extension_has_nonzero_coverage_for_missing_taxonomy_classes() -> None:
    frequencies = class_frequency(classify_traces(load_extension_traces("test")))
    for escalation_class in (
        EscalationClass.DELEGATION_CHAIN_ABUSE,
        EscalationClass.PERSISTENCE_HIJACK,
        EscalationClass.MODEL_ARTIFACT_SUBSTITUTION,
        EscalationClass.MULTI_AGENT_COLLUSION,
    ):
        assert frequencies[escalation_class.value] == 10


def test_extension_policy_blocks_attacks_without_false_positives() -> None:
    report = evaluate_traces(load_extension_traces("test"), load_extension_profile())
    assert report["attack_count"] == 40
    assert report["blocked_count"] == 40
    assert report["benign_count"] == 40
    assert report["false_positive_count"] == 0


def test_extension_families_are_not_public_benchmark_families() -> None:
    extension_families = {trace["family"] for trace in load_extension_traces("test")}
    public_families = {
        "prompt_injection",
        "control_token",
        "parser_confusion",
        "tool_hijack",
        "tool_poisoning",
        "data_exfil",
        "priv_esc",
    }
    assert extension_families.isdisjoint(public_families)
