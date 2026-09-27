from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class EscalationClass(StrEnum):
    TOOL_SCOPE_EXPANSION = "tool scope expansion"
    CONFUSED_DEPUTY = "confused deputy"
    CREDENTIAL_EXFILTRATION = "credential or secret exfiltration"
    DELEGATION_CHAIN_ABUSE = "delegation chain abuse"
    PERSISTENCE_HIJACK = "persistence or hijack"
    MODEL_ARTIFACT_SUBSTITUTION = "model or artifact substitution"
    MULTI_AGENT_COLLUSION = "multi-agent collusion"
    INDIRECT_PROMPT_INJECTION = "indirect prompt injection into tool calls"
    PARSER_CONTROL_CONFUSION = "parser control confusion"
    BENIGN = "benign"


class PrivilegeBoundary(StrEnum):
    TOOL = "tool grant"
    NETWORK = "network destination"
    CREDENTIAL_MATERIAL = "credential material handling"
    DELEGATION = "delegation chain"
    DURABLE_STATE = "durable state"
    ARTIFACT = "model or artifact integrity"
    AGENT_GROUP = "agent group"
    CONTEXT = "context authority"
    NONE = "none"


@dataclass(frozen=True)
class TaxonomyEntry:
    name: EscalationClass
    vector: str
    boundary: PrivilegeBoundary
    precondition: str
    observable_signal: str
    mitigating_control: str
    security_threats: tuple[str, ...]
    mitre_artificial_intelligence_techniques: tuple[str, ...]
    decision_rule: str


TAXONOMY: tuple[TaxonomyEntry, ...] = (
    TaxonomyEntry(
        EscalationClass.TOOL_SCOPE_EXPANSION,
        "A run invokes a tool or operation outside the task, role, or current posture grant.",
        PrivilegeBoundary.TOOL,
        "The agent can request tools whose risk exceeds the task grant.",
        "Sensitive tool names, missing scopes, degraded posture, or admin-like tool output.",
        "Check task-bound scopes and deny privileged tools unless posture and trust are sufficient.",
        ("Elevation of privilege", "Tampering"),
        ("AML.TA0005", "AML.TA0006"),
        "Choose when the malicious step uses a privileged tool or asks for a broader tool grant.",
    ),
    TaxonomyEntry(
        EscalationClass.CONFUSED_DEPUTY,
        "A trusted tool description or tool output causes the agent to spend authority for another party.",
        PrivilegeBoundary.CONTEXT,
        "The agent treats untrusted tool-originated text as an instruction source.",
        "Tool output or server metadata asks for hidden, admin, or credential-related behavior.",
        "Separate data from instructions and require provenance on authority-changing requests.",
        ("Spoofing", "Elevation of privilege"),
        ("AML.T0051",),
        "Choose when tool-originated text, not the user, induces the escalation.",
    ),
    TaxonomyEntry(
        EscalationClass.CREDENTIAL_EXFILTRATION,
        "A run moves secret material or a reversible transform of it into an argument or egress path.",
        PrivilegeBoundary.CREDENTIAL_MATERIAL,
        "Secret material is reachable by the agent or appears in retrieved context.",
        "Listed secrets, credential-like arguments, or requests to include tokens in outbound data.",
        "Use handles instead of values, scan arguments, and block value-bearing egress.",
        ("Information disclosure",),
        ("AML.T0057",),
        "Choose when secrets or credential substitutes are the protected asset being moved.",
    ),
    TaxonomyEntry(
        EscalationClass.DELEGATION_CHAIN_ABUSE,
        "A run delegates action to an unapproved recipient, endpoint, mailbox, or collector.",
        PrivilegeBoundary.DELEGATION,
        "The task permits some communication or network action.",
        "Recipients or endpoints fall outside the approved organization domain or task recipient set.",
        "Bind recipients and endpoints to the original task and require explicit delegation grants.",
        ("Spoofing", "Information disclosure"),
        ("AML.T0054",),
        "Choose when the boundary crossed is who receives the effect, not which tool is used.",
    ),
    TaxonomyEntry(
        EscalationClass.PERSISTENCE_HIJACK,
        "A run modifies durable configuration, startup files, scheduled actions, or tool definitions.",
        PrivilegeBoundary.DURABLE_STATE,
        "The agent has write access to locations that affect future runs.",
        "Writes to startup paths, tool manifests, policy bundles, or scheduled execution state.",
        "Require separate administrative approval and append-only review for durable changes.",
        ("Persistence", "Tampering"),
        ("AML.T0018",),
        "Choose when the attempted privilege survives beyond the current task.",
    ),
    TaxonomyEntry(
        EscalationClass.MODEL_ARTIFACT_SUBSTITUTION,
        "A run swaps or tampers with the model, adapter, tool binary, or other executable artifact.",
        PrivilegeBoundary.ARTIFACT,
        "The runtime loads artifacts from mutable local or remote storage.",
        "Hash mismatch, untrusted publisher, or artifact path change.",
        "Verify measurements against golden references before tool execution.",
        ("Tampering",),
        ("AML.T0015",),
        "Choose when the escalation is achieved by changing executable artifacts.",
    ),
    TaxonomyEntry(
        EscalationClass.MULTI_AGENT_COLLUSION,
        "Several agents combine individually allowed steps into a forbidden aggregate operation.",
        PrivilegeBoundary.AGENT_GROUP,
        "Agents can share state, identifiers, destinations, or staged outputs.",
        "Repeated hand-offs, shared collectors, or correlated partial exfiltration.",
        "Correlate related tasks and enforce aggregate policy limits.",
        ("Repudiation", "Information disclosure"),
        ("unmapped",),
        "Choose when no single step is sufficient but the coordinated sequence crosses a boundary.",
    ),
    TaxonomyEntry(
        EscalationClass.INDIRECT_PROMPT_INJECTION,
        "Untrusted retrieved text changes the intended user task into a tool action.",
        PrivilegeBoundary.CONTEXT,
        "The agent retrieves documents or messages before selecting tools.",
        "Retrieved text says to ignore, override, upload, forward, or bypass the user task.",
        "Treat retrieved content as data and require user-task consistency checks.",
        ("Spoofing", "Elevation of privilege"),
        ("AML.T0051",),
        "Choose when retrieved content supplies the malicious instruction.",
    ),
    TaxonomyEntry(
        EscalationClass.PARSER_CONTROL_CONFUSION,
        "Control tokens, partial frames, or parser ambiguities induce unintended tool dispatch.",
        PrivilegeBoundary.CONTEXT,
        "The runtime parses mixed natural language and tool frames.",
        "Control tokens, private channel text, partial frames, or tolerant parser triggers.",
        "Use structured envelopes and reject control text from untrusted channels.",
        ("Tampering", "Elevation of privilege"),
        ("AML.T0051",),
        "Choose when parser confusion, not ordinary instruction text, is the immediate vector.",
    ),
    TaxonomyEntry(
        EscalationClass.BENIGN,
        "No privilege boundary is crossed by the trace.",
        PrivilegeBoundary.NONE,
        "The task stays within granted scope.",
        "Approved destinations, scoped tools, handles rather than secret values, and clean context.",
        "Allow only after normal policy gates pass.",
        ("none",),
        ("not applicable",),
        "Choose only when no escalation rule matches.",
    ),
)

ENTRY_BY_CLASS = {entry.name: entry for entry in TAXONOMY}
