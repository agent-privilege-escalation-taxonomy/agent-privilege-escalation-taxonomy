# Threat Model

The protected assets are tool grants, local files, shell execution, network egress, secret leases, model artifacts, policy state, durable configuration, inter-agent delegation, and audit records.

The attacker can inject retrieved text, influence tool output, request unapproved destinations, try to move secret material or reversible encodings, induce parser control confusion, propose durable state changes, or coordinate multiple agents so each step appears locally acceptable.

The reference policy is intentionally conservative: valid workload identity, valid attestation, task-scoped tool grants, approved destinations, clean context, and argument leak checks must pass before a side-effecting step is allowed. The benchmark results show that these gates are insufficient for several taxonomy classes, especially confused deputy behavior.
