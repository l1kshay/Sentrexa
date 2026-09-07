"""Turn detections into alerts and link them to their contributing logs.

``create_alerts`` is idempotent: alerts are upserted on their ``dedup_key`` with
ON CONFLICT DO NOTHING, so replaying the same detections (or re-running the whole
cycle) never produces a duplicate alert. Contributing-log rows in
``alert_log_links`` are upserted the same way.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.models import Alert, AlertLogLink
from detection.rules_engine import Detection

HIGH_SEVERITIES = frozenset({"high", "critical"})


@dataclass
class AlertResult:
    new_alert_ids: list[int]
    linked_alert_ids: list[int]      # every alert touched this run (new + existing)
    links_created: int

    @property
    def created(self) -> int:
        return len(self.new_alert_ids)


def create_alerts(session: Session, detections: Sequence[Detection]) -> AlertResult:
    if not detections:
        return AlertResult([], [], 0)

    alert_rows = [
        {
            "rule_id": d.rule_id,
            "triggered_at": d.triggered_at,
            "source_ip": d.source_ip,
            "username": d.username,
            "severity": d.severity,
            "status": "New",
            "dedup_key": d.dedup_key,
        }
        for d in _dedup(detections)
    ]

    new_by_key: dict[str, int] = {
        row.dedup_key: row.alert_id
        for row in session.execute(
            pg_insert(Alert)
            .values(alert_rows)
            .on_conflict_do_nothing(index_elements=["dedup_key"])
            .returning(Alert.alert_id, Alert.dedup_key)
        )
    }

    # resolve alert_ids for detections whose alert already existed
    all_by_key = dict(new_by_key)
    missing = [d.dedup_key for d in detections if d.dedup_key not in all_by_key]
    if missing:
        for aid, key in session.execute(
            select(Alert.alert_id, Alert.dedup_key).where(Alert.dedup_key.in_(missing))
        ):
            all_by_key[key] = aid

    link_rows = [
        {"alert_id": all_by_key[d.dedup_key], "log_id": log_id}
        for d in detections
        for log_id in d.log_ids
        if d.dedup_key in all_by_key
    ]
    links_created = 0
    if link_rows:
        res = session.execute(
            pg_insert(AlertLogLink)
            .values(link_rows)
            .on_conflict_do_nothing(index_elements=["alert_id", "log_id"])
            .returning(AlertLogLink.log_id)
        )
        links_created = len(res.fetchall())

    return AlertResult(
        new_alert_ids=sorted(new_by_key.values()),
        linked_alert_ids=sorted(set(all_by_key.values())),
        links_created=links_created,
    )


def _dedup(detections: Sequence[Detection]) -> list[Detection]:
    """Collapse detections that share a dedup_key within a single run."""
    seen: dict[str, Detection] = {}
    for d in detections:
        seen.setdefault(d.dedup_key, d)
    return list(seen.values())
