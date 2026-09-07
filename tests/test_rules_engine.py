"""Phase 3 tests: the detection rule engine.

Per the spec's testing requirements:
* true positives against every seeded attack scenario,
* true negatives against benign traffic,
* at least one edge case per rule (notably: a burst one attempt short of the
  brute-force threshold must NOT fire),
* re-running detection on an already-processed batch creates nothing new.

The detector functions are pure (no DB), so most tests build LogRecord/RuleSpec
directly. The idempotency test is a DB integration test and auto-skips without
a database.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from config.settings import settings
from detection.rules_engine import (
    Detection,
    LogRecord,
    RuleSpec,
    detect_brute_force,
    detect_off_hours_login,
    detect_privilege_escalation,
    run_rules,
)
from simulation.attack_scenarios import (
    brute_force_burst,
    build_all_scenarios,
    off_hours_login,
    privilege_escalation,
)
from simulation.common import make_rng, window

SIM = settings.simulation
END = datetime(2026, 9, 7, 12, 0, 0, tzinfo=timezone.utc)
START, _ = window(END, 168)

BF_RULE = RuleSpec(1, "SSH brute-force burst", "brute_force", "high", 10, 5, "T1110.001", {})
OH_RULE = RuleSpec(
    2, "Off-hours successful login", "off_hours_login", "medium",
    None, None, "T1078.003", {"start_hour": 20, "end_hour": 6},
)
PE_RULE = RuleSpec(
    3, "Privilege escalation via sudo keywords", "privilege_escalation", "high",
    None, None, "T1548.003",
    {"keywords": sorted({k.lower() for k in SIM.privilege_escalation_keywords})},
)


def to_records(events, start_id: int = 1) -> list[LogRecord]:
    return [
        LogRecord(
            log_id=i,
            timestamp=e.timestamp,
            source_system=e.source_system,
            source_ip=e.source_ip,
            username=e.username,
            event_type=e.event_type,
            status=e.status,
            raw_message=e.raw_message,
        )
        for i, e in enumerate(events, start=start_id)
    ]


def login(ts: datetime, *, ok: bool, ip: str, user: str = "ariwan") -> LogRecord:
    verb = "Accepted" if ok else "Failed"
    return LogRecord(
        log_id=0, timestamp=ts, source_system="auth", source_ip=ip, username=user,
        event_type="login", status="success" if ok else "failure",
        raw_message=f"{ts:%Y-%m-%dT%H:%M:%SZ} app01 sshd[1]: {verb} password for {user} from {ip} port 5 ssh2",
    )


# --------------------------------------------------------------------------- #
# Brute force
# --------------------------------------------------------------------------- #
class TestBruteForce:
    def test_seeded_burst_is_detected(self) -> None:
        sc = brute_force_burst(
            make_rng(1), START, END,
            attempts=SIM.brute_force_attempts,
            window_minutes=SIM.brute_force_window_min,
            targets=SIM.internal_users[:3],
        )
        dets = detect_brute_force(BF_RULE, to_records(sc.events))
        assert len(dets) == 1
        d = dets[0]
        assert d.source_ip == sc.focus_ip
        assert len(d.log_ids) == SIM.brute_force_attempts  # the trailing success is excluded
        assert d.severity == "high"

    def test_one_attempt_short_of_threshold_does_not_fire(self) -> None:
        sc = brute_force_burst(
            make_rng(2), START, END, attempts=9, window_minutes=5,
            targets=SIM.internal_users[:3], follow_with_success=False,
        )
        assert detect_brute_force(BF_RULE, to_records(sc.events)) == []

    def test_exactly_threshold_fires(self) -> None:
        sc = brute_force_burst(
            make_rng(3), START, END, attempts=10, window_minutes=5,
            targets=SIM.internal_users[:2], follow_with_success=False,
        )
        assert len(detect_brute_force(BF_RULE, to_records(sc.events))) == 1

    def test_failures_spread_beyond_window_do_not_fire(self) -> None:
        base = START + timedelta(days=1)
        recs = [login(base + timedelta(minutes=4 * i), ok=False, ip="203.0.113.9")
                for i in range(12)]  # 12 fails, 4 min apart -> never 10 within 5 min
        assert detect_brute_force(BF_RULE, recs) == []

    def test_distributed_failures_from_many_ips_do_not_fire(self) -> None:
        base = START + timedelta(days=1)
        recs = [login(base + timedelta(seconds=i), ok=False, ip=f"203.0.113.{i}")
                for i in range(30)]
        assert detect_brute_force(BF_RULE, recs) == []

    def test_dedup_key_is_stable_and_daily(self) -> None:
        sc = brute_force_burst(
            make_rng(4), START, END, attempts=12, window_minutes=3,
            targets=SIM.internal_users[:3],
        )
        a = detect_brute_force(BF_RULE, to_records(sc.events))[0]
        b = detect_brute_force(BF_RULE, to_records(sc.events))[0]
        assert a.dedup_key == b.dedup_key
        assert a.dedup_key.startswith(f"brute_force:{BF_RULE.rule_id}:{sc.focus_ip}:")


# --------------------------------------------------------------------------- #
# Off-hours login
# --------------------------------------------------------------------------- #
class TestOffHoursLogin:
    def test_seeded_off_hours_login_is_detected(self) -> None:
        sc = off_hours_login(make_rng(5), START, END, off_hour=3, user="epatel")
        dets = detect_off_hours_login(OH_RULE, to_records(sc.events))
        assert len(dets) == 1
        assert dets[0].username == "epatel"
        assert dets[0].severity == "medium"

    def test_business_hours_login_does_not_fire(self) -> None:
        ts = START.replace(hour=13, minute=30) + timedelta(days=1)
        assert detect_off_hours_login(OH_RULE, [login(ts, ok=True, ip="10.1.4.5")]) == []

    def test_window_boundaries(self) -> None:
        day = (START + timedelta(days=2)).replace(minute=0, second=0, microsecond=0)
        fires = detect_off_hours_login(OH_RULE, [login(day.replace(hour=20), ok=True, ip="10.1.4.5")])
        quiet = detect_off_hours_login(OH_RULE, [login(day.replace(hour=19), ok=True, ip="10.1.4.5")])
        early = detect_off_hours_login(OH_RULE, [login(day.replace(hour=5), ok=True, ip="10.1.4.5")])
        assert len(fires) == 1 and early and quiet == []

    def test_failed_off_hours_login_does_not_fire(self) -> None:
        ts = (START + timedelta(days=1)).replace(hour=2)
        assert detect_off_hours_login(OH_RULE, [login(ts, ok=False, ip="203.0.113.9")]) == []

    def test_non_login_event_ignored(self) -> None:
        ts = (START + timedelta(days=1)).replace(hour=2)
        sudo = LogRecord(
            log_id=1, timestamp=ts, source_system="auth", source_ip=None,
            username="epatel", event_type="sudo", status="success",
            raw_message=f"{ts:%Y-%m-%dT%H:%M:%SZ} app01 sudo:  epatel : TTY=pts/0 ; PWD=/h ; USER=root ; COMMAND=/bin/df",
        )
        assert detect_off_hours_login(OH_RULE, [sudo]) == []


# --------------------------------------------------------------------------- #
# Privilege escalation
# --------------------------------------------------------------------------- #
class TestPrivilegeEscalation:
    def test_seeded_privesc_is_detected(self) -> None:
        sc = privilege_escalation(
            make_rng(6), START, END, user="dkhan",
            keywords=SIM.privilege_escalation_keywords,
        )
        dets = detect_privilege_escalation(PE_RULE, to_records(sc.events))
        assert len(dets) == sc.expected_min_matches >= 2
        assert all(d.severity == "high" for d in dets)

    def test_benign_sudo_does_not_fire(self) -> None:
        ts = (START + timedelta(days=1)).replace(hour=10)
        rec = LogRecord(
            log_id=1, timestamp=ts, source_system="auth", source_ip=None,
            username="ariwan", event_type="sudo", status="success",
            raw_message=f"{ts:%Y-%m-%dT%H:%M:%SZ} app01 sudo:  ariwan : TTY=pts/0 ; PWD=/h ; USER=root ; COMMAND=/usr/bin/apt-get update",
        )
        assert detect_privilege_escalation(PE_RULE, [rec]) == []

    def test_keyword_match_is_case_insensitive(self) -> None:
        ts = (START + timedelta(days=1)).replace(hour=10)
        rec = LogRecord(
            log_id=1, timestamp=ts, source_system="auth", source_ip=None,
            username="ariwan", event_type="sudo", status="success",
            raw_message=f"{ts:%Y-%m-%dT%H:%M:%SZ} app01 sudo:  ariwan : TTY=pts/0 ; PWD=/h ; USER=root ; COMMAND=SUDO SU -",
        )
        assert len(detect_privilege_escalation(PE_RULE, [rec])) == 1

    def test_non_auth_line_with_keyword_ignored(self) -> None:
        ts = (START + timedelta(days=1)).replace(hour=10)
        web = LogRecord(
            log_id=1, timestamp=ts, source_system="web", source_ip="203.0.113.9",
            username=None, event_type="http_request", status="allowed",
            raw_message='203.0.113.9 - - [01/Sep/2026:10:00:00 +0000] "GET /?x=sudo su HTTP/1.1" 200 1 "-" "curl"',
        )
        assert detect_privilege_escalation(PE_RULE, [web]) == []

    def test_empty_keyword_list_never_fires(self) -> None:
        empty = RuleSpec(3, "pe", "privilege_escalation", "high", None, None,
                         "T1548.003", {"keywords": []})
        ts = (START + timedelta(days=1)).replace(hour=10)
        rec = LogRecord(
            log_id=1, timestamp=ts, source_system="auth", source_ip=None,
            username="x", event_type="sudo", status="success",
            raw_message="... COMMAND=sudo su",
        )
        assert detect_privilege_escalation(empty, [rec]) == []


# --------------------------------------------------------------------------- #
# Engine dispatch + true negatives on benign traffic
# --------------------------------------------------------------------------- #
class TestEngine:
    def test_run_rules_covers_every_scenario(self) -> None:
        rng = make_rng(1337)
        events = []
        for sc in build_all_scenarios(rng, START, END, SIM):
            events += sc.events
        dets = run_rules([BF_RULE, OH_RULE, PE_RULE], to_records(events))
        kinds = {d.rule_type for d in dets}
        assert kinds == {"brute_force", "off_hours_login", "privilege_escalation"}

    def test_benign_business_hours_traffic_produces_no_detections(self) -> None:
        from simulation.generators.auth_log_generator import generate_auth_events
        from simulation.generators.firewall_log_generator import generate_firewall_events
        from simulation.generators.web_log_generator import generate_web_events

        rng = make_rng(99)
        events = generate_auth_events(
            rng, count=1500, start=START, end=END,
            users=SIM.internal_users, admin_users=SIM.admin_users,
        )
        events += generate_web_events(rng, count=800, start=START, end=END, users=SIM.internal_users)
        events += generate_firewall_events(rng, count=800, start=START, end=END)
        # keep only clearly in-business-hours auth so this is a clean true negative
        events = [
            e for e in events
            if not (e.source_system == "auth" and not (8 <= e.timestamp.hour < 19))
        ]
        dets = run_rules([BF_RULE, OH_RULE, PE_RULE], to_records(events))
        assert dets == [], [d.dedup_key for d in dets]

    def test_unknown_rule_type_is_ignored(self) -> None:
        bogus = RuleSpec(9, "bogus", "port_scan", "low", 1, 1, "T0000", {})
        assert run_rules([bogus], to_records([login(END, ok=False, ip="1.2.3.4")])) == []


# --------------------------------------------------------------------------- #
# Idempotency (DB integration)
# --------------------------------------------------------------------------- #
@pytest.mark.db
class TestIdempotency:
    def test_detection_does_not_reprocess_a_committed_batch(
        self, clean_slate, admin_engine, cleanup_batch
    ) -> None:
        from detection.runner import run_detection
        from ingestion.load import ingest_feed

        batch = cleanup_batch(f"test-{uuid.uuid4()}")
        # 12 failed logins from one IP within 2 minutes = a brute-force burst
        base = datetime(2026, 9, 2, 3, 0, 0, tzinfo=timezone.utc)
        lines = [
            '{"source_system":"auth","raw_message":"%s app01 sshd[%d]: Failed password for ariwan from 203.0.113.77 port %d ssh2"}'
            % ((base + timedelta(seconds=10 * i)).strftime("%Y-%m-%dT%H:%M:%SZ"), i, 4000 + i)
            for i in range(12)
        ]
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            feed = Path(td) / "f.ndjson"
            feed.write_text("\n".join(lines) + "\n", encoding="utf-8")
            ingest_feed(feed, batch_name=batch)

            with admin_engine.begin() as conn:
                unprocessed_before = conn.execute(
                    text("SELECT count(*) FROM logs_raw "
                         "WHERE ingest_batch = :b AND processed = false"),
                    {"b": batch},
                ).scalar_one()
            assert unprocessed_before == 12

            first = run_detection(commit=True)
            assert first.logs_scanned == 12
            assert any(d.rule_type == "brute_force" for d in first.detections)

            second = run_detection(commit=True)

            with admin_engine.begin() as conn:
                still_unprocessed = conn.execute(
                    text("SELECT count(*) FROM logs_raw "
                         "WHERE ingest_batch = :b AND processed = false"),
                    {"b": batch},
                ).scalar_one()
        assert still_unprocessed == 0
        assert second.logs_scanned == 0
        assert second.detections == []
