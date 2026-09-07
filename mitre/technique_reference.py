"""Curated static MITRE ATT&CK reference.

Only the techniques the Sentrexa detection rules actually map to - not a mirror
of the full ATT&CK matrix. Each rule in ``detection_rules`` points at one of
these via ``mitre_technique_id``.

Mapping rationale
-----------------
brute_force          -> T1110.001  Brute Force: Password Guessing
                        Repeated failed SSH auth from one source = classic
                        online password guessing.
off_hours_login      -> T1078.003  Valid Accounts: Local Accounts
                        A real local account authenticating successfully at an
                        unusual hour - valid credentials, anomalous use.
privilege_escalation -> T1548.003  Abuse Elevation Control Mechanism:
                        Sudo and Sudo Caching
                        sudo invocations that grant or widen admin rights.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Technique:
    technique_id: str
    technique_name: str
    tactic: str
    description: str


TECHNIQUES: tuple[Technique, ...] = (
    Technique(
        technique_id="T1110.001",
        technique_name="Brute Force: Password Guessing",
        tactic="Credential Access",
        description=(
            "Adversaries guess passwords for accounts when the password is not "
            "known, typically via many rapid authentication attempts against a "
            "service such as SSH."
        ),
    ),
    Technique(
        technique_id="T1078.003",
        technique_name="Valid Accounts: Local Accounts",
        tactic="Defense Evasion",
        description=(
            "Adversaries use credentials of a local account to blend in with "
            "normal activity. Successful authentication at anomalous times is a "
            "signal of misused-but-valid local accounts."
        ),
    ),
    Technique(
        technique_id="T1548.003",
        technique_name="Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        tactic="Privilege Escalation",
        description=(
            "Adversaries abuse sudo (or its cached credentials) to execute "
            "commands as root or to grant an account persistent administrative "
            "group membership."
        ),
    ),
)

# rule_type -> technique_id, the single source of the rule->ATT&CK mapping.
RULE_TYPE_TO_TECHNIQUE: dict[str, str] = {
    "brute_force": "T1110.001",
    "off_hours_login": "T1078.003",
    "privilege_escalation": "T1548.003",
}


def technique_by_id(technique_id: str) -> Technique:
    for t in TECHNIQUES:
        if t.technique_id == technique_id:
            return t
    raise KeyError(technique_id)
