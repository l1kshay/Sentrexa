"""Phase 1 tests: log simulation foundation.

These cover schema validity, seed determinism, and - most importantly - that
each seeded attack scenario actually contains the events the matching Phase 3
rule will need. The detection engine's own true/false-positive suite lives in
tests/test_rules_engine.py (Phase 3).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from config.settings import get_settings
from simulation.attack_scenarios import (
    RULE_BRUTE_FORCE,
    RULE_OFF_HOURS,
    RULE_PRIV_ESC,
    build_all_scenarios,
)
from simulation.common import make_rng, window
from simulation.dataset import build_dataset
from simulation.generators.auth_log_generator import generate_auth_events
from simulation.generators.firewall_log_generator import generate_firewall_events
from simulation.generators.web_log_generator import generate_web_events
from simulation.schema import (
    EVENT_LOGIN,
    SOURCE_AUTH,
    SOURCE_FIREWALL,
    SOURCE_WEB,
    STATUS_FAILURE,
    STATUS_SUCCESS,
    LogEvent,
    LogEventError,
)

SIM = get_settings().simulation
END = datetime(2026, 9, 7, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def win() -> tuple[datetime, datetime]:
    return window(END, 168)


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #
class TestSchema:
    def test_valid_event_roundtrips(self) -> None:
        ev = LogEvent(
            timestamp=END,
            source_system=SOURCE_AUTH,
            source_ip="10.1.4.9",
            username="ariwan",
            event_type=EVENT_LOGIN,
            status=STATUS_SUCCESS,
            raw_message="x",
        )
        assert ev.disk_record() == {"source_system": "auth", "raw_message": "x"}
        assert ev.oracle_record()["timestamp"].endswith("Z")

    def test_naive_timestamp_rejected(self) -> None:
        with pytest.raises(LogEventError):
            LogEvent(
                timestamp=datetime(2026, 1, 1),
                source_system=SOURCE_AUTH,
                source_ip="10.0.0.1",
                username=None,
                event_type=EVENT_LOGIN,
                status=STATUS_SUCCESS,
                raw_message="x",
            )

    def test_status_must_match_source(self) -> None:
        with pytest.raises(LogEventError):
            LogEvent(
                timestamp=END,
                source_system=SOURCE_WEB,
                source_ip="10.0.0.1",
                username=None,
                event_type="http_request",
                status=STATUS_SUCCESS,  # web uses allowed/blocked
                raw_message="x",
            )

    def test_bad_ip_rejected(self) -> None:
        with pytest.raises(LogEventError):
            LogEvent(
                timestamp=END,
                source_system=SOURCE_FIREWALL,
                source_ip="not-an-ip",
                username=None,
                event_type="connection",
                status="allowed",
                raw_message="x",
            )


# --------------------------------------------------------------------------- #
# Generators
# --------------------------------------------------------------------------- #
class TestGenerators:
    def test_exact_counts_and_sources(self, win) -> None:
        start, end = win
        rng = make_rng(1)
        auth = generate_auth_events(
            rng, count=300, start=start, end=end,
            users=SIM.internal_users, admin_users=SIM.admin_users,
        )
        web = generate_web_events(
            rng, count=300, start=start, end=end, users=SIM.internal_users,
        )
        fw = generate_firewall_events(rng, count=300, start=start, end=end)

        assert len(auth) == len(web) == len(fw) == 300
        assert all(e.source_system == SOURCE_AUTH for e in auth)
        assert all(e.source_system == SOURCE_WEB for e in web)
        assert all(e.source_system == SOURCE_FIREWALL for e in fw)
        # every event validated on construction; timestamps inside the window
        for e in auth + web + fw:
            assert start <= e.timestamp <= end + timedelta(seconds=60)

    def test_firewall_has_no_username(self, win) -> None:
        start, end = win
        fw = generate_firewall_events(make_rng(2), count=100, start=start, end=end)
        assert all(e.username is None for e in fw)

    def test_benign_auth_has_no_privesc_keywords(self, win) -> None:
        start, end = win
        auth = generate_auth_events(
            make_rng(3), count=500, start=start, end=end,
            users=SIM.internal_users, admin_users=SIM.admin_users,
        )
        for e in auth:
            for kw in SIM.privilege_escalation_keywords:
                assert kw not in e.raw_message

    def test_seed_determinism(self, win) -> None:
        start, end = win
        a = generate_web_events(make_rng(7), count=200, start=start, end=end,
                                users=SIM.internal_users)
        b = generate_web_events(make_rng(7), count=200, start=start, end=end,
                                users=SIM.internal_users)
        assert [e.raw_message for e in a] == [e.raw_message for e in b]


# --------------------------------------------------------------------------- #
# Off-hours window logic
# --------------------------------------------------------------------------- #
class TestOffHoursWindow:
    def test_wraps_past_midnight(self) -> None:
        s = get_settings().simulation  # default 20 -> 6
        assert s.is_off_hours(23)
        assert s.is_off_hours(3)
        assert s.is_off_hours(5)
        assert not s.is_off_hours(6)
        assert not s.is_off_hours(12)
        assert not s.is_off_hours(19)
        assert s.is_off_hours(20)


# --------------------------------------------------------------------------- #
# Seeded attack scenarios
# --------------------------------------------------------------------------- #
class TestScenarios:
    @pytest.fixture
    def scenarios(self, win):
        start, end = win
        return build_all_scenarios(make_rng(1337), start, end, SIM)

    def test_one_scenario_per_rule(self, scenarios) -> None:
        rule_types = {s.expected_rule_type for s in scenarios}
        assert rule_types == {RULE_BRUTE_FORCE, RULE_OFF_HOURS, RULE_PRIV_ESC}

    def test_brute_force_shape(self, scenarios) -> None:
        bf = next(s for s in scenarios if s.expected_rule_type == RULE_BRUTE_FORCE)
        fails = [e for e in bf.events if e.status == STATUS_FAILURE]
        assert len(fails) == SIM.brute_force_attempts
        assert bf.expected_min_matches == SIM.brute_force_attempts
        # single source IP for the whole burst
        assert {e.source_ip for e in bf.events} == {bf.focus_ip}
        # all failures within the configured burst window (+ small jitter)
        span = max(e.timestamp for e in fails) - min(e.timestamp for e in fails)
        assert span <= timedelta(minutes=SIM.brute_force_window_min) + timedelta(seconds=10)
        # exactly one trailing success (the breach)
        assert sum(1 for e in bf.events if e.status == STATUS_SUCCESS) == 1

    def test_brute_force_one_short_still_builds(self, win) -> None:
        """A burst sized one below the (default 10) threshold must still be a
        well-formed scenario - the Phase 3 edge-case test relies on being able
        to under-fill it."""
        from simulation.attack_scenarios import brute_force_burst

        start, end = win
        sc = brute_force_burst(
            make_rng(9), start, end, attempts=9, window_minutes=5,
            targets=SIM.internal_users[:3], follow_with_success=False,
        )
        assert sum(1 for e in sc.events if e.status == STATUS_FAILURE) == 9
        assert all(e.source_ip == sc.focus_ip for e in sc.events)

    def test_off_hours_scenario(self, scenarios) -> None:
        oh = next(s for s in scenarios if s.expected_rule_type == RULE_OFF_HOURS)
        assert len(oh.events) == 1
        ev = oh.events[0]
        assert ev.status == STATUS_SUCCESS
        assert ev.event_type == EVENT_LOGIN
        assert SIM.is_off_hours(ev.timestamp.hour)
        assert ev.username == oh.focus_username

    def test_privilege_escalation_scenario(self, scenarios) -> None:
        pe = next(s for s in scenarios if s.expected_rule_type == RULE_PRIV_ESC)
        hits = [
            e for e in pe.events
            if any(kw in e.raw_message for kw in SIM.privilege_escalation_keywords)
        ]
        assert len(hits) >= 2
        assert pe.expected_min_matches == len(hits)
        assert {e.username for e in pe.events} == {pe.focus_username}


# --------------------------------------------------------------------------- #
# Full dataset + manifest
# --------------------------------------------------------------------------- #
class TestDataset:
    def test_full_feed_is_deterministic(self) -> None:
        a = build_dataset(seed=1337, benign_events=1500, window_hours=168,
                          end=END, inject_malformed=6)
        b = build_dataset(seed=1337, benign_events=1500, window_hours=168,
                          end=END, inject_malformed=6)
        assert a.lines == b.lines

    def test_manifest_indexes_point_at_the_right_lines(self, built_dataset) -> None:
        for sc in built_dataset.scenarios:
            oracle_raws = {e["raw_message"] for e in sc.oracle()["events"]}
            assert len(sc.event_line_indexes) >= sc.expected_min_matches
            for idx in sc.event_line_indexes:
                rec = json.loads(built_dataset.lines[idx])
                assert rec["raw_message"] in oracle_raws

    def test_events_are_time_ordered(self, feed_records) -> None:
        times = [
            r["raw_message"] for r in feed_records
            if r and isinstance(r, dict) and "raw_message" in r
        ]
        assert len(times) > 1000  # sanity: most lines are real

    def test_malformed_lines_are_actually_bad(self, built_dataset, feed_records) -> None:
        assert len(built_dataset.malformed_line_indexes) == 6
        for idx in built_dataset.malformed_line_indexes:
            rec = feed_records[idx]
            bad = (
                rec is None
                or "source_system" not in rec
                or "raw_message" not in rec
                or not rec["raw_message"]
                or rec["source_system"] not in {"auth", "web", "firewall"}
            )
            assert bad, f"line {idx} was expected to be malformed: {built_dataset.lines[idx]!r}"

    def test_seeded_attacks_are_a_small_fraction_of_the_feed(self, built_dataset) -> None:
        seeded = sum(len(s.event_line_indexes) for s in built_dataset.scenarios)
        assert seeded < built_dataset.benign_count * 0.05
