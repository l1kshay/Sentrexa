"""Phase 4 tests: alert generation, incident escalation, status workflows.

All are DB integration tests (auto-skip without a database). Workflow tests use a
rollback-scoped session so they leave nothing behind; pipeline tests use the
cleanup_batch fixture.
"""

from __future__ import annotations

import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from alerting.incident_manager import (
    WorkflowError,
    escalate_high_severity,
    set_alert_status,
    set_incident_status,
)
from db.models import Alert, Incident

pytestmark = pytest.mark.db


@pytest.fixture
def rollback_session(admin_engine):
    conn = admin_engine.connect()
    trans = conn.begin()
    session = Session(bind=conn)
    try:
        yield session
    finally:
        session.close()
        trans.rollback()
        conn.close()


def _mk_alert(session: Session, *, severity: str, status: str = "New") -> Alert:
    a = Alert(
        rule_id=1,  # seeded rule
        triggered_at=datetime.now(timezone.utc),
        source_ip="203.0.113.9",
        username="tester",
        severity=severity,
        status=status,
        dedup_key=f"test:{uuid.uuid4()}",
    )
    session.add(a)
    session.flush()
    return a


# --------------------------------------------------------------------------- #
# Escalation
# --------------------------------------------------------------------------- #
class TestEscalation:
    def test_only_high_and_critical_escalate(self, rollback_session) -> None:
        high = _mk_alert(rollback_session, severity="high")
        crit = _mk_alert(rollback_session, severity="critical")
        med = _mk_alert(rollback_session, severity="medium")
        low = _mk_alert(rollback_session, severity="low")

        escalated = set(escalate_high_severity(rollback_session))
        assert escalated == {high.alert_id, crit.alert_id}
        assert med.alert_id not in escalated and low.alert_id not in escalated

    def test_escalation_is_idempotent(self, rollback_session) -> None:
        a = _mk_alert(rollback_session, severity="high")
        first = escalate_high_severity(rollback_session)
        second = escalate_high_severity(rollback_session)
        assert a.alert_id in first
        assert second == []
        n = rollback_session.execute(
            text("SELECT count(*) FROM incidents WHERE alert_id = :a"), {"a": a.alert_id}
        ).scalar_one()
        assert n == 1

    def test_dismissed_high_alert_does_not_escalate(self, rollback_session) -> None:
        a = _mk_alert(rollback_session, severity="high", status="Dismissed")
        assert escalate_high_severity(rollback_session) == []
        assert a.alert_id not in escalate_high_severity(rollback_session)


# --------------------------------------------------------------------------- #
# Alert status workflow
# --------------------------------------------------------------------------- #
class TestAlertWorkflow:
    def test_valid_transitions(self, rollback_session) -> None:
        a = _mk_alert(rollback_session, severity="medium")
        set_alert_status(rollback_session, a.alert_id, "Acknowledged")
        assert a.status == "Acknowledged"
        set_alert_status(rollback_session, a.alert_id, "Dismissed")
        assert a.status == "Dismissed"

    def test_new_can_go_straight_to_dismissed(self, rollback_session) -> None:
        a = _mk_alert(rollback_session, severity="low")
        set_alert_status(rollback_session, a.alert_id, "Dismissed")
        assert a.status == "Dismissed"

    @pytest.mark.parametrize("frm, to", [
        ("Acknowledged", "New"),
        ("Dismissed", "Acknowledged"),
        ("New", "Closed"),
    ])
    def test_invalid_transitions_raise(self, rollback_session, frm, to) -> None:
        a = _mk_alert(rollback_session, severity="medium", status=frm)
        with pytest.raises(WorkflowError):
            set_alert_status(rollback_session, a.alert_id, to)

    def test_unknown_alert_raises(self, rollback_session) -> None:
        with pytest.raises(WorkflowError):
            set_alert_status(rollback_session, 999_999_999, "Acknowledged")


# --------------------------------------------------------------------------- #
# Incident status workflow
# --------------------------------------------------------------------------- #
class TestIncidentWorkflow:
    def _open_incident(self, session: Session) -> Incident:
        a = _mk_alert(session, severity="high")
        escalate_high_severity(session)
        session.flush()
        return session.query(Incident).filter_by(alert_id=a.alert_id).one()

    def test_open_to_in_review_to_closed(self, rollback_session) -> None:
        inc = self._open_incident(rollback_session)
        set_incident_status(rollback_session, inc.incident_id, "In Review",
                            assigned_to="analyst1")
        assert inc.status == "In Review" and inc.assigned_to == "analyst1"
        set_incident_status(rollback_session, inc.incident_id, "Closed",
                            resolution_notes="Confirmed false positive; user on call.")
        assert inc.status == "Closed"
        assert inc.closed_at is not None
        assert "false positive" in inc.resolution_notes

    def test_closing_requires_resolution_notes(self, rollback_session) -> None:
        inc = self._open_incident(rollback_session)
        with pytest.raises(WorkflowError):
            set_incident_status(rollback_session, inc.incident_id, "Closed")
        with pytest.raises(WorkflowError):
            set_incident_status(rollback_session, inc.incident_id, "Closed",
                                resolution_notes="   ")

    def test_closed_is_terminal(self, rollback_session) -> None:
        inc = self._open_incident(rollback_session)
        set_incident_status(rollback_session, inc.incident_id, "Closed",
                            resolution_notes="done")
        with pytest.raises(WorkflowError):
            set_incident_status(rollback_session, inc.incident_id, "In Review")


# --------------------------------------------------------------------------- #
# End-to-end: detections -> alerts -> incidents via the runner
# --------------------------------------------------------------------------- #
def _brute_feed(path: Path) -> None:
    base = datetime(2026, 9, 2, 3, 0, 0, tzinfo=timezone.utc)
    lines = [
        '{"source_system":"auth","raw_message":"%s app01 sshd[%d]: Failed password for ariwan from 203.0.113.88 port %d ssh2"}'
        % ((base + timedelta(seconds=8 * i)).strftime("%Y-%m-%dT%H:%M:%SZ"), i, 5000 + i)
        for i in range(14)
    ]
    # plus a benign off-hours login (medium, should NOT escalate)
    lines.append(
        '{"source_system":"auth","raw_message":"2026-09-02T03:30:00Z app01 sshd[99]: '
        'Accepted password for bthomas from 10.1.4.5 port 6000 ssh2"}'
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestPipelineAlerting:
    def test_detections_create_alerts_incidents_and_links(
        self, clean_slate, admin_engine, cleanup_batch
    ) -> None:
        from detection.runner import run_detection
        from ingestion.load import ingest_feed

        batch = cleanup_batch(f"test-{uuid.uuid4()}")
        with tempfile.TemporaryDirectory() as td:
            feed = Path(td) / "f.ndjson"
            _brute_feed(feed)
            ingest_feed(feed, batch_name=batch)

            first = run_detection(commit=True)
            assert first.alerts_created == 2          # brute_force + off_hours
            assert first.incidents_created == 1        # only the brute_force (high)

            second = run_detection(commit=True)
            assert second.alerts_created == 0
            assert second.incidents_created == 0

        with admin_engine.begin() as conn:
            bf = conn.execute(text(
                "SELECT a.alert_id, a.severity, a.status, count(l.log_id) AS n "
                "FROM alerts a JOIN alert_log_links l USING (alert_id) "
                "WHERE a.dedup_key LIKE 'brute_force:%%203.0.113.88%%' "
                "GROUP BY a.alert_id, a.severity, a.status"
            )).one()
            assert bf.severity == "high" and bf.status == "New" and bf.n == 14
            inc = conn.execute(text(
                "SELECT status FROM incidents WHERE alert_id = :a"), {"a": bf.alert_id}
            ).scalar_one()
            assert inc == "Open"
