"""Seeded attack scenarios.

Each scenario injects a small, deterministic burst of events that a specific
Phase 3 detection rule is expected to catch. Every scenario also carries the
metadata tests and the run manifest need: which rule type should fire, the
focus IP/username, and how many contributing events exist.

Rule coverage:
    brute_force_burst      -> rule_type "brute_force"
    off_hours_login        -> rule_type "off_hours_login"
    privilege_escalation   -> rule_type "privilege_escalation"
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .common import external_ip, internal_ip, random_time, random_time_at_hour
from .generators.auth_log_generator import login_event, sudo_event
from .schema import LogEvent

RULE_BRUTE_FORCE = "brute_force"
RULE_OFF_HOURS = "off_hours_login"
RULE_PRIV_ESC = "privilege_escalation"


@dataclass
class SeededScenario:
    scenario_id: str
    expected_rule_type: str
    description: str
    events: list[LogEvent]
    focus_ip: str | None = None
    focus_username: str | None = None
    expected_min_matches: int = 1
    # populated by the dataset builder once the full feed is ordered
    event_line_indexes: list[int] = field(default_factory=list)

    def oracle(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "expected_rule_type": self.expected_rule_type,
            "description": self.description,
            "focus_ip": self.focus_ip,
            "focus_username": self.focus_username,
            "expected_min_matches": self.expected_min_matches,
            "event_line_indexes": self.event_line_indexes,
            "events": [e.oracle_record() for e in self.events],
        }


# --------------------------------------------------------------------------- #
# Scenario builders
# --------------------------------------------------------------------------- #
def brute_force_burst(
    rng: random.Random,
    start: datetime,
    end: datetime,
    *,
    attempts: int,
    window_minutes: int,
    targets: list[str],
    follow_with_success: bool = True,
) -> SeededScenario:
    """One external IP, many failed SSH logins inside a short window.

    Emits ``attempts`` "Failed password" events from a single attacker IP against
    a small set of usernames, spread across ``window_minutes``. Optionally ends
    with one "Accepted password" (a successful breach) shortly after.
    """
    attacker_ip = external_ip(rng)
    burst_start = random_time(rng, start, end - timedelta(minutes=window_minutes + 2))
    span = window_minutes * 60

    events: list[LogEvent] = []
    for i in range(attempts):
        offset = span * (i / max(attempts - 1, 1)) + rng.uniform(-3, 3)
        dt = burst_start + timedelta(seconds=max(offset, 0))
        events.append(
            login_event(
                dt, ok=False, user=rng.choice(targets), ip=attacker_ip, rng=rng,
                invalid_user=rng.random() < 0.3,
            )
        )
    matches = len(events)
    if follow_with_success:
        dt = burst_start + timedelta(seconds=span + rng.uniform(10, 40))
        events.append(
            login_event(dt, ok=True, user=targets[0], ip=attacker_ip, rng=rng)
        )

    events.sort(key=lambda e: e.timestamp)
    return SeededScenario(
        scenario_id="brute_force_burst",
        expected_rule_type=RULE_BRUTE_FORCE,
        description=(
            f"{attempts} failed SSH logins from {attacker_ip} within "
            f"{window_minutes} min"
            + (", followed by one successful login" if follow_with_success else "")
        ),
        events=events,
        focus_ip=attacker_ip,
        focus_username=None,
        expected_min_matches=matches,
    )


def off_hours_login(
    rng: random.Random,
    start: datetime,
    end: datetime,
    *,
    off_hour: int,
    user: str,
) -> SeededScenario:
    """A single successful interactive login during the off-hours window."""
    dt = random_time_at_hour(rng, start, end, off_hour)
    ip = internal_ip(rng)
    ev = login_event(dt, ok=True, user=user, ip=ip, rng=rng)
    return SeededScenario(
        scenario_id="off_hours_login",
        expected_rule_type=RULE_OFF_HOURS,
        description=f"Successful login by {user} from {ip} at ~{off_hour:02d}:00 UTC (off-hours)",
        events=[ev],
        focus_ip=ip,
        focus_username=user,
        expected_min_matches=1,
    )


def privilege_escalation(
    rng: random.Random,
    start: datetime,
    end: datetime,
    *,
    user: str,
    keywords: list[str],
) -> SeededScenario:
    """A normal login followed by sudo commands containing priv-esc keywords."""
    kw = rng.sample(keywords, k=min(2, len(keywords)))
    ip = internal_ip(rng)
    t0 = random_time(rng, start, end - timedelta(minutes=10))

    events: list[LogEvent] = [
        login_event(t0, ok=True, user=user, ip=ip, rng=rng),
    ]
    for i, keyword in enumerate(kw, start=1):
        events.append(
            sudo_event(
                t0 + timedelta(minutes=i, seconds=rng.uniform(0, 30)),
                user=user,
                command=keyword if keyword.startswith(("sudo", "usermod", "net ", "GRANT"))
                else f"/bin/bash -c '{keyword}'",
                ip=ip,
                rng=rng,
            )
        )
    return SeededScenario(
        scenario_id="privilege_escalation",
        expected_rule_type=RULE_PRIV_ESC,
        description=f"{user} runs sudo commands containing: {', '.join(kw)}",
        events=events,
        focus_ip=ip,
        focus_username=user,
        expected_min_matches=len(kw),
    )


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def build_all_scenarios(
    rng: random.Random,
    start: datetime,
    end: datetime,
    sim_settings,
) -> list[SeededScenario]:
    """Build one instance of every scenario, driven by ``config.settings``."""
    targets = rng.sample(sim_settings.internal_users, k=3)
    off_hour = _pick_off_hour(sim_settings)
    return [
        brute_force_burst(
            rng, start, end,
            attempts=sim_settings.brute_force_attempts,
            window_minutes=sim_settings.brute_force_window_min,
            targets=targets,
        ),
        off_hours_login(
            rng, start, end,
            off_hour=off_hour,
            user=rng.choice(sim_settings.internal_users),
        ),
        privilege_escalation(
            rng, start, end,
            user=rng.choice(sim_settings.internal_users),
            keywords=sim_settings.privilege_escalation_keywords,
        ),
    ]


def _pick_off_hour(sim_settings) -> int:
    for hour in (2, 3, 1, 0, 23, 22, 4, 5, 21, 20):
        if sim_settings.is_off_hours(hour):
            return hour
    return 3
