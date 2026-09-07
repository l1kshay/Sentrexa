"""Config-driven, rule-based detection engine.

Rules are read from the ``detection_rules`` table (see ``detection/seed.py``);
nothing here hardcodes a threshold, window, keyword list, or severity. Each
``rule_type`` has one pure detector that takes a ``RuleSpec`` plus a batch of
``LogRecord`` and returns ``Detection`` objects - no database access inside the
detectors, so they are trivially unit-testable.

Detectors
---------
brute_force          sliding-window count of failed SSH logins per source IP
off_hours_login      successful login whose UTC hour is inside the rule's window
privilege_escalation an auth line whose text contains a configured keyword
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import DetectionRule, LogRaw

# --------------------------------------------------------------------------- #
# Plain data the detectors operate on (decoupled from the ORM)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class RuleSpec:
    rule_id: int
    rule_name: str
    rule_type: str
    severity: str
    threshold_value: int | None
    time_window_minutes: int | None
    mitre_technique_id: str
    params: dict = field(default_factory=dict)

    @classmethod
    def from_orm(cls, r: DetectionRule) -> "RuleSpec":
        return cls(
            rule_id=r.rule_id,
            rule_name=r.rule_name,
            rule_type=r.rule_type,
            severity=r.severity,
            threshold_value=r.threshold_value,
            time_window_minutes=r.time_window_minutes,
            mitre_technique_id=r.mitre_technique_id,
            params=dict(r.params or {}),
        )


@dataclass(frozen=True, slots=True)
class LogRecord:
    log_id: int
    timestamp: datetime
    source_system: str
    source_ip: str | None
    username: str | None
    event_type: str
    status: str
    raw_message: str

    @classmethod
    def from_orm(cls, r: LogRaw) -> "LogRecord":
        return cls(
            log_id=r.log_id,
            timestamp=r.timestamp,
            source_system=r.source_system,
            source_ip=str(r.source_ip) if r.source_ip is not None else None,
            username=r.username,
            event_type=r.event_type,
            status=r.status,
            raw_message=r.raw_message,
        )


@dataclass(frozen=True, slots=True)
class Detection:
    rule_id: int
    rule_type: str
    severity: str
    triggered_at: datetime
    source_ip: str | None
    username: str | None
    log_ids: tuple[int, ...]
    dedup_key: str


# --------------------------------------------------------------------------- #
# Detectors
# --------------------------------------------------------------------------- #
def detect_brute_force(rule: RuleSpec, logs: Sequence[LogRecord]) -> list[Detection]:
    threshold = rule.threshold_value or 0
    window = timedelta(minutes=rule.time_window_minutes or 0)
    if threshold <= 0 or window <= timedelta(0):
        return []

    fails_by_ip: dict[str, list[LogRecord]] = defaultdict(list)
    for l in logs:
        if (
            l.source_system == "auth"
            and l.event_type == "login"
            and l.status == "failure"
            and l.source_ip
        ):
            fails_by_ip[l.source_ip].append(l)

    out: list[Detection] = []
    for ip, evs in fails_by_ip.items():
        evs.sort(key=lambda l: l.timestamp)
        contributing: set[int] = set()
        left = 0
        for right in range(len(evs)):
            while evs[right].timestamp - evs[left].timestamp > window:
                left += 1
            if right - left + 1 >= threshold:
                for k in range(left, right + 1):
                    contributing.add(evs[k].log_id)
        if contributing:
            hit = [l for l in evs if l.log_id in contributing]
            triggered_at = max(l.timestamp for l in hit)
            day = triggered_at.date().isoformat()
            out.append(
                Detection(
                    rule_id=rule.rule_id,
                    rule_type=rule.rule_type,
                    severity=rule.severity,
                    triggered_at=triggered_at,
                    source_ip=ip,
                    username=None,
                    log_ids=tuple(sorted(contributing)),
                    dedup_key=f"brute_force:{rule.rule_id}:{ip}:{day}",
                )
            )
    return out


def _is_off_hours(hour: int, start: int, end: int) -> bool:
    if start == end:
        return False
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end


def detect_off_hours_login(rule: RuleSpec, logs: Sequence[LogRecord]) -> list[Detection]:
    start = int(rule.params.get("start_hour", 20))
    end = int(rule.params.get("end_hour", 6))
    out: list[Detection] = []
    for l in logs:
        if (
            l.source_system == "auth"
            and l.event_type == "login"
            and l.status == "success"
            and _is_off_hours(l.timestamp.hour, start, end)
        ):
            out.append(
                Detection(
                    rule_id=rule.rule_id,
                    rule_type=rule.rule_type,
                    severity=rule.severity,
                    triggered_at=l.timestamp,
                    source_ip=l.source_ip,
                    username=l.username,
                    log_ids=(l.log_id,),
                    dedup_key=(
                        f"off_hours:{rule.rule_id}:{l.username}:"
                        f"{l.timestamp.isoformat()}"
                    ),
                )
            )
    return out


def detect_privilege_escalation(
    rule: RuleSpec, logs: Sequence[LogRecord]
) -> list[Detection]:
    keywords = [str(k).lower() for k in rule.params.get("keywords", [])]
    if not keywords:
        return []
    out: list[Detection] = []
    for l in logs:
        if l.source_system != "auth":
            continue
        msg = l.raw_message.lower()
        if any(k in msg for k in keywords):
            out.append(
                Detection(
                    rule_id=rule.rule_id,
                    rule_type=rule.rule_type,
                    severity=rule.severity,
                    triggered_at=l.timestamp,
                    source_ip=l.source_ip,
                    username=l.username,
                    log_ids=(l.log_id,),
                    dedup_key=f"priv_esc:{rule.rule_id}:{l.log_id}",
                )
            )
    return out


DETECTORS: dict[str, Callable[[RuleSpec, Sequence[LogRecord]], list[Detection]]] = {
    "brute_force": detect_brute_force,
    "off_hours_login": detect_off_hours_login,
    "privilege_escalation": detect_privilege_escalation,
}


def run_rules(rules: Sequence[RuleSpec], logs: Sequence[LogRecord]) -> list[Detection]:
    """Apply every rule to the batch and return all detections, time-ordered."""
    detections: list[Detection] = []
    for rule in rules:
        detector = DETECTORS.get(rule.rule_type)
        if detector is None:
            continue
        detections.extend(detector(rule, logs))
    detections.sort(key=lambda d: (d.triggered_at, d.rule_id))
    return detections


# --------------------------------------------------------------------------- #
# Database glue
# --------------------------------------------------------------------------- #
def load_active_rules(session: Session) -> list[RuleSpec]:
    rows = session.execute(
        select(DetectionRule).where(DetectionRule.is_active.is_(True))
    ).scalars().all()
    return [RuleSpec.from_orm(r) for r in rows]


def load_unprocessed_logs(session: Session, *, limit: int | None = None) -> list[LogRecord]:
    stmt = (
        select(LogRaw)
        .where(LogRaw.processed.is_(False))
        .order_by(LogRaw.timestamp, LogRaw.log_id)
    )
    if limit:
        stmt = stmt.limit(limit)
    return [LogRecord.from_orm(r) for r in session.execute(stmt).scalars().all()]
