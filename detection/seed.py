"""Seed ``mitre_techniques`` and ``detection_rules``.

Idempotent: ``python -m detection.seed`` can be run repeatedly. MITRE rows come
from the curated reference in ``mitre/technique_reference.py``. The three rule
rows are seeded here once - after that the ``detection_rules`` table is the sole
authority; the engine never reads these literals.

The privilege-escalation keyword list is bridged from ``config.settings`` at
seed time so the simulator and the detector start in agreement; edit the row's
``params`` in the database to change it thereafter.
"""

from __future__ import annotations

from sqlalchemy.dialects.postgresql import insert as pg_insert

from config.settings import settings
from db.engine import session_scope
from db.models import DetectionRule, MitreTechnique
from mitre.technique_reference import RULE_TYPE_TO_TECHNIQUE, TECHNIQUES


def _rule_rows() -> list[dict]:
    keywords = sorted({k.lower() for k in settings.simulation.privilege_escalation_keywords})
    return [
        {
            "rule_name": "SSH brute-force burst",
            "rule_type": "brute_force",
            "threshold_value": 10,
            "time_window_minutes": 5,
            "mitre_technique_id": RULE_TYPE_TO_TECHNIQUE["brute_force"],
            "severity": "high",
            "is_active": True,
            "params": {},
        },
        {
            "rule_name": "Off-hours successful login",
            "rule_type": "off_hours_login",
            "threshold_value": None,
            "time_window_minutes": None,
            "mitre_technique_id": RULE_TYPE_TO_TECHNIQUE["off_hours_login"],
            "severity": "medium",
            "is_active": True,
            "params": {"start_hour": 20, "end_hour": 6},
        },
        {
            "rule_name": "Privilege escalation via sudo keywords",
            "rule_type": "privilege_escalation",
            "threshold_value": None,
            "time_window_minutes": None,
            "mitre_technique_id": RULE_TYPE_TO_TECHNIQUE["privilege_escalation"],
            "severity": "high",
            "is_active": True,
            "params": {"keywords": keywords},
        },
    ]


def seed() -> tuple[int, int]:
    """Upsert techniques + rules. Returns (technique_count, rule_count)."""
    with session_scope("rw") as s:
        for t in TECHNIQUES:
            s.execute(
                pg_insert(MitreTechnique)
                .values(
                    technique_id=t.technique_id,
                    technique_name=t.technique_name,
                    tactic=t.tactic,
                    description=t.description,
                )
                .on_conflict_do_update(
                    index_elements=["technique_id"],
                    set_={
                        "technique_name": t.technique_name,
                        "tactic": t.tactic,
                        "description": t.description,
                    },
                )
            )

        for r in _rule_rows():
            s.execute(
                pg_insert(DetectionRule)
                .values(**r)
                .on_conflict_do_update(
                    index_elements=["rule_name"],
                    set_={
                        "rule_type": r["rule_type"],
                        "threshold_value": r["threshold_value"],
                        "time_window_minutes": r["time_window_minutes"],
                        "mitre_technique_id": r["mitre_technique_id"],
                        "severity": r["severity"],
                        "is_active": r["is_active"],
                        "params": r["params"],
                    },
                )
            )

    return len(TECHNIQUES), len(_rule_rows())


def main() -> int:
    techs, rules = seed()
    print(f"seeded {techs} MITRE techniques, {rules} detection rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
