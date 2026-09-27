---- MODULE DenyByDefault ----
EXTENDS Naturals, TLC
CONSTANTS Requests
VARIABLES request, identityValid, attested, policyPass, trustHigh, decision

Init ==
  /\ request \in Requests
  /\ identityValid \in BOOLEAN
  /\ attested \in BOOLEAN
  /\ policyPass \in BOOLEAN
  /\ trustHigh \in BOOLEAN
  /\ decision = "deny"

AllowCondition == identityValid /\ attested /\ policyPass /\ trustHigh

Next ==
  \/ /\ AllowCondition
     /\ decision' = "allow"
     /\ UNCHANGED <<request, identityValid, attested, policyPass, trustHigh>>
  \/ /\ ~AllowCondition
     /\ decision' = "deny"
     /\ UNCHANGED <<request, identityValid, attested, policyPass, trustHigh>>

NoBypass == decision = "allow" => AllowCondition
Spec == Init /\ [][Next]_<<request, identityValid, attested, policyPass, trustHigh, decision>>
====
