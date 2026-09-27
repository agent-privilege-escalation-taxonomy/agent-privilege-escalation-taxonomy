from __future__ import annotations

import ast
import importlib.util
import re
from pathlib import Path

import pytest

PUBLIC_SCHEMA_AND_RUNTIME_TOKENS = {
    "access",
    "action",
    "action.",
    "admin",
    "admin-like",
    "administrative",
    "after",
    "agent",
    "allow",
    "allowed",
    "appears",
    "approval",
    "approved",
    "argument",
    "arguments",
    "artifact",
    "artifacts",
    "asks",
    "assistant",
    "attack",
    "attestation",
    "audit",
    "before",
    "benign",
    "beyond",
    "block",
    "boundary",
    "broker",
    "build",
    "bypass",
    "calendar",
    "calendar.create",
    "call",
    "channel",
    "change",
    "check",
    "clean",
    "cleanup",
    "collection",
    "collector.",
    "command",
    "content",
    "context",
    "context.",
    "credential",
    "credential-like",
    "current",
    "data",
    "database",
    "db.admin",
    "db.query",
    "degraded",
    "delete",
    "deny",
    "deploy",
    "description",
    "details",
    "diagnostic",
    "discusses",
    "dispatch.",
    "documentation",
    "domain",
    "drop",
    "egress.",
    "email",
    "email.send",
    "encoded",
    "endpoint",
    "escalation",
    "evidence",
    "execute",
    "execution.",
    "fail",
    "files",
    "forward",
    "frame",
    "from",
    "fs.delete",
    "fs.read",
    "fs.write",
    "grant",
    "handoff",
    "harmless",
    "hashes",
    "help",
    "hidden",
    "hijack",
    "history",
    "http.get",
    "http.post",
    "iam.grant",
    "identifiers",
    "identity",
    "ignore",
    "immediate",
    "include",
    "injection",
    "inspect",
    "instruction",
    "instruction.",
    "instructions",
    "into",
    "invalid",
    "json",
    "lacks",
    "language",
    "lease",
    "lesson",
    "list",
    "local",
    "maintenance",
    "malicious",
    "material",
    "meeting",
    "message",
    "metadata",
    "missing",
    "mode",
    "model",
    "natural",
    "network",
    "never",
    "normal",
    "note",
    "notify",
    "object",
    "only",
    "opaque",
    "operation",
    "operation.",
    "ordinary",
    "outbound",
    "output",
    "output.",
    "outside",
    "override",
    "parser",
    "partial",
    "path",
    "path.",
    "payments.transfer",
    "policy",
    "post",
    "posture",
    "previous",
    "private",
    "privileged",
    "profile.json",
    "prompt",
    "protected",
    "public",
    "query",
    "questionable",
    "quotes",
    "read",
    "reference",
    "references",
    "replayed",
    "report",
    "request",
    "requester",
    "requests",
    "require",
    "required",
    "response",
    "retrieved",
    "reversible",
    "review",
    "revoked",
    "role",
    "runtime",
    "says",
    "scope",
    "scope.",
    "search",
    "secret",
    "secret:",
    "secrets",
    "security",
    "send",
    "sensitive",
    "server",
    "share",
    "shell.exec",
    "sink",
    "split",
    "stale",
    "start",
    "status",
    "stop",
    "streaming",
    "structured",
    "submit",
    "summarizing",
    "support",
    "task",
    "task.",
    "test",
    "text",
    "that",
    "this",
    "token",
    "token_ref",
    "tolerant",
    "tool",
    "tools",
    "tools.",
    "traces",
    "training",
    "trust",
    "unrelated",
    "untrusted",
    "update",
    "upload",
    "user",
    "uses",
    "value",
    "values",
    "verify",
    "weak",
    "whose",
    "with",
    "within",
    "without",
    "write",
}


def _string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _string_value(node.left)
        right = _string_value(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _docstring_node_ids(tree: ast.AST) -> set[int]:
    docstring_nodes: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(
                node,
                ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef,
            )
            and node.body
            and isinstance(node.body[0], ast.Expr)
        ):
            first = node.body[0].value
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                docstring_nodes.add(id(first))
    return docstring_nodes


def _string_literals(path: Path) -> list[str]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    docstring_nodes = _docstring_node_ids(tree)
    values: list[str] = []
    for node in ast.walk(tree):
        if id(node) in docstring_nodes:
            continue
        value = _string_value(node)
        if value is not None:
            values.append(value)
    return values


def _regex_name(node: ast.Call, parents: dict[ast.AST, ast.AST]) -> str:
    parent = parents.get(node)
    if isinstance(parent, ast.Assign) and len(parent.targets) == 1:
        target = parent.targets[0]
        if isinstance(target, ast.Name):
            return target.id
    return ""


def _regex_alternation_count(pattern: str) -> int:
    in_class = False
    escaped = False
    count = 0
    for ch in pattern:
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        elif ch == "|" and not in_class:
            count += 1
    return count + 1 if count else 0


def _compiled_regexes(path: Path) -> list[tuple[str, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    patterns: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "compile"
            and isinstance(func.value, ast.Name)
            and func.value.id == "re"
            and node.args
        ):
            pattern = _string_value(node.args[0])
            if pattern is not None:
                patterns.append((_regex_name(node, parents), pattern))
    return patterns


@pytest.mark.skipif(
    importlib.util.find_spec("zero_trust_agent_benchmark") is None,
    reason="zero-trust-agent-benchmark not installed",
)
def test_src_string_literals_do_not_copy_benchmark_generator_tokens() -> None:
    from zero_trust_agent_benchmark.generator import literal_tokens

    src = Path(__file__).resolve().parents[1] / "src"
    source_tokens: set[str] = set()
    for path in src.rglob("*.py"):
        for literal in _string_literals(path):
            source_tokens.update(re.findall(r"[a-z][a-z0-9_.:-]{3,}", literal.lower()))

    forbidden = literal_tokens() - PUBLIC_SCHEMA_AND_RUNTIME_TOKENS
    assert sorted(source_tokens & forbidden) == []


def test_src_has_no_large_content_keyword_regexes() -> None:
    allowed_generic_patterns = {
        "CONTROL_TEXT_RE",
        "SUSPICIOUS_TEXT_RE",
        "SAFE_TEXT_RE",
        "PARSER_HAZARD_RE",
        "POSTURE_FAILURE_RE",
    }
    src = Path(__file__).resolve().parents[1] / "src"
    offenders: list[str] = []
    for path in src.rglob("*.py"):
        for name, pattern in _compiled_regexes(path):
            if name in allowed_generic_patterns:
                continue
            if _regex_alternation_count(pattern) > 10:
                offenders.append(f"{path.relative_to(src)}:{name}")
    assert offenders == []
