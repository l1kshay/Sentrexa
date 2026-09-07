"""Incident escalation and the alert / incident status workflows.

* High-severity alerts auto-escalate into exactly one incident (one-to-one, via
  the UNIQUE constraint on ``incidents.alert_id``) - idempotent.
* Status transitions are validated:
      alert:    New -> Acknowledged | Dismissed ;  Acknowledged -> Dismissed
      incident: Open -> In Review | Closed ;  In Review -> Closed | Open
  Closing an incident requires resolution notes and stamps ``closed_at``.

These helpers back the analyst actions on the Phase 5 dashboard.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import exists, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.models import Alert, Incident

HIGH_SEVERITIES = frozenset({"high", "critical"})

_ALERT_TRANSITIONS: dict[str, set[str]] = {
    "New": {"Acknowledged", "Dismissed"},
    "Acknowledged": {"Dismissed"},
    "Dismissed": set(),
}
_INCIDENT_TRANSITIONS: dict[str, set[str]] = {
    "Open": {"In Review", "Closed"},
    "In Review": {"Closed", "Open"},
    "Closed": set(),
}


class WorkflowError(ValueError):
    pass


def escalate_high_severity(session: Session) -> list[int]:
    """Create an incident for every high/critical alert that lacks one.

    Returns the alert_ids escalated this call. Safe to run repeatedly.
    """
    candidates = session.execute(
        select(Alert.alert_id)
        .where(
            Alert.severity.in_(HIGH_SEVERITIES),
            Alert.status != "Dismissed",
            ~exists().where(Incident.alert_id == Alert.alert_id),
        )
        .order_by(Alert.alert_id)
    ).scalars().all()

    if candidates:
        session.execute(
            pg_insert(Incident)
            .values([{"alert_id": aid, "status": "Open"} for aid in candidates])
            .on_conflict_do_nothing(index_elements=["alert_id"])
        )
    return list(candidates)


def set_alert_status(session: Session, alert_id: int, new_status: str) -> Alert:
    alert = session.get(Alert, alert_id)
    if alert is None:
        raise WorkflowError(f"alert {alert_id} not found")
    allowed = _ALERT_TRANSITIONS.get(alert.status, set())
    if new_status not in allowed:
        raise WorkflowError(
            f"invalid alert transition {alert.status!r} -> {new_status!r} "
            f"(allowed: {sorted(allowed) or 'none'})"
        )
    alert.status = new_status
    return alert


def set_incident_status(
    session: Session,
    incident_id: int,
    new_status: str,
    *,
    resolution_notes: str | None = None,
    assigned_to: str | None = None,
) -> Incident:
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise WorkflowError(f"incident {incident_id} not found")
    allowed = _INCIDENT_TRANSITIONS.get(incident.status, set())
    if new_status not in allowed:
        raise WorkflowError(
            f"invalid incident transition {incident.status!r} -> {new_status!r} "
            f"(allowed: {sorted(allowed) or 'none'})"
        )

    if new_status == "Closed":
        if not (resolution_notes and resolution_notes.strip()):
            raise WorkflowError("closing an incident requires resolution_notes")
        incident.resolution_notes = resolution_notes.strip()
        incident.closed_at = datetime.now(timezone.utc)
    else:
        incident.closed_at = None

    if assigned_to is not None:
        incident.assigned_to = assigned_to
    incident.status = new_status
    return incident


def assign_incident(session: Session, incident_id: int, assignee: str) -> Incident:
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise WorkflowError(f"incident {incident_id} not found")
    incident.assigned_to = assignee
    return incident
