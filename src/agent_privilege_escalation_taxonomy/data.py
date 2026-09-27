from __future__ import annotations

import hashlib
import importlib.resources
import importlib.util
import json
from collections.abc import Iterable
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Literal, cast

TraceRecord = dict[str, Any]

DATASET_VERSION = "zero-trust-agent-benchmark-dataset-v4.1"
PINNED_SHA256 = {
    "all": "698bde6021459ac1a2ddf51f41897b7c79614e20dc906712dcceb6f51ebb7676",
    "dev": "4b6fcd37944e7ad85295805e8b73a4507680a87c9a09c5b1201ab43ef02d1e31",
    "test": "d065bab9bed145490579cd7add6a574c6e23c21c0ea4525dc1c14b0fc15acd2b",
}
EXTENSION_VERSION = "agent-privilege-escalation-taxonomy-extension-v1"
EXTENSION_DIR = Path("data") / "extension-v1"


def benchmark_available() -> bool:
    return importlib.util.find_spec("zero_trust_agent_benchmark") is not None


def local_traces_dir() -> Path | None:
    candidates = [Path("../zero-trust-agent-benchmark/traces")]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _packaged_split_bytes(split: str) -> bytes | None:
    try:
        package_root = importlib.resources.files("zero_trust_agent_benchmark")
        candidates = [package_root / "_data" / "traces" / f"{split}.jsonl"]
        for candidate in candidates:
            if candidate.is_file():
                return candidate.read_bytes()
    except (FileNotFoundError, ModuleNotFoundError):
        return None
    return None


def split_bytes(split: str) -> bytes:
    if split not in PINNED_SHA256:
        raise ValueError(f"unknown split: {split}")
    local = local_traces_dir()
    if local is not None:
        return (local / f"{split}.jsonl").read_bytes()
    packaged = _packaged_split_bytes(split)
    if packaged is None:
        raise RuntimeError("zero-trust-agent-benchmark traces are unavailable")
    return packaged


def assert_pinned_split(split: str) -> str:
    observed = hashlib.sha256(split_bytes(split)).hexdigest()
    expected = PINNED_SHA256[split]
    if observed != expected:
        raise ValueError(f"benchmark split {split} sha256 {observed} did not match {expected}")
    return observed


def assert_pinned_dataset(splits: Iterable[str] = ("dev", "test")) -> dict[str, str]:
    return {split: assert_pinned_split(split) for split in splits}


def _as_record(value: Any) -> TraceRecord:
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    if isinstance(value, dict):
        return value
    raise TypeError(f"unsupported trace type: {type(value)!r}")


def load_profile() -> dict[str, Any]:
    from zero_trust_agent_benchmark.profile import profile

    return profile()


def load_traces(split: str = "test") -> list[TraceRecord]:
    assert_pinned_split(split)
    if split == "all":
        lines = split_bytes("all").decode("utf-8").splitlines()
        return [json.loads(line) for line in lines]
    if split not in {"dev", "test"}:
        raise ValueError(f"unknown split: {split}")
    from zero_trust_agent_benchmark import load_traces as load_benchmark_traces

    path = local_traces_dir()
    loaded = load_benchmark_traces(
        cast(Literal["dev", "test"], split), str(path) if path is not None else None
    )
    return [_as_record(trace) for trace in loaded]


def extension_manifest() -> dict[str, str]:
    manifest_path = EXTENSION_DIR / "manifest.sha256"
    rows: dict[str, str] = {}
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        digest, name = line.split(maxsplit=1)
        rows[name] = digest
    return rows


def assert_extension_split(split: str) -> str:
    if split not in {"dev", "test"}:
        raise ValueError(f"unknown extension split: {split}")
    path = EXTENSION_DIR / f"{split}.jsonl"
    observed = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = extension_manifest()[path.name]
    if observed != expected:
        raise ValueError(f"extension split {split} sha256 {observed} did not match {expected}")
    return observed


def load_extension_profile() -> dict[str, Any]:
    value = json.loads((EXTENSION_DIR / "profile.json").read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError("extension profile must be an object")
    return value


def load_extension_traces(split: str = "test") -> list[TraceRecord]:
    assert_extension_split(split)
    lines = (EXTENSION_DIR / f"{split}.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


def iter_steps(trace: TraceRecord) -> Iterable[dict[str, Any]]:
    for step in trace.get("steps", []):
        if isinstance(step, dict):
            yield step
