"""Shared building blocks for the log generators.

Everything here is deterministic given a seeded ``random.Random``. Generators
never call the global ``random`` module or an unseeded Faker, so a fixed
``SIM_SEED`` reproduces a byte-identical dataset.

IP hygiene: "external" addresses are drawn only from the RFC 5737
documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) so the
simulator can never emit a real routable address, even by accident.
"""

from __future__ import annotations

import ipaddress
import random
from datetime import datetime, timedelta, timezone

from faker import Faker

# -- deterministic RNG / Faker ------------------------------------------------- #

def make_rng(seed: int) -> random.Random:
    return random.Random(seed)


def make_faker(seed: int) -> Faker:
    fake = Faker()
    fake.seed_instance(seed)
    return fake


# -- IP pools ---------------------------------------------------------------- #
_INTERNAL_WORKSTATIONS = list(ipaddress.ip_network("10.1.4.0/24").hosts())
_INTERNAL_SERVERS = list(ipaddress.ip_network("10.1.0.0/24").hosts())
_EXTERNAL_DOC_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]
_EXTERNAL_POOL = [str(h) for net in _EXTERNAL_DOC_NETS for h in net.hosts()]


def internal_ip(rng: random.Random, *, server: bool = False) -> str:
    pool = _INTERNAL_SERVERS if server else _INTERNAL_WORKSTATIONS
    return str(rng.choice(pool))


def external_ip(rng: random.Random) -> str:
    return rng.choice(_EXTERNAL_POOL)


def stable_external_ips(rng: random.Random, n: int) -> list[str]:
    """A fixed sample of external IPs to act as a recurring 'known' population."""
    return rng.sample(_EXTERNAL_POOL, k=min(n, len(_EXTERNAL_POOL)))


# -- time helpers ---------------------------------------------------------- #

def window(end: datetime, hours: int) -> tuple[datetime, datetime]:
    """(start, end) spanning ``hours`` and ending at ``end`` (both tz-aware UTC)."""
    end = end.astimezone(timezone.utc)
    return end - timedelta(hours=hours), end


def random_time(rng: random.Random, start: datetime, end: datetime) -> datetime:
    span = (end - start).total_seconds()
    return start + timedelta(seconds=rng.uniform(0, span))


def random_business_time(
    rng: random.Random,
    start: datetime,
    end: datetime,
    *,
    off_hours_fraction: float = 0.05,
    business_start: int = 8,
    business_end: int = 19,
) -> datetime:
    """A timestamp in [start, end) biased toward working hours.

    ~``1 - off_hours_fraction`` of results land in [business_start, business_end)
    UTC; the rest are spread across the remaining hours. Used for benign human
    activity so that the "off-hours login" rule has a genuinely anomalous
    minority to catch instead of ~40% of all logins.
    """
    total_days = max(int((end - start).total_seconds() // 86400), 1)
    day = start + timedelta(days=rng.randrange(total_days))
    day = day.replace(minute=0, second=0, microsecond=0)

    business = list(range(business_start, business_end))
    after = [h for h in range(24) if h not in business]
    hour = rng.choice(business) if rng.random() > off_hours_fraction else rng.choice(after)

    candidate = day.replace(hour=hour) + timedelta(seconds=rng.uniform(0, 3600))
    if candidate < start:
        candidate += timedelta(days=1)
    if candidate >= end:
        candidate -= timedelta(days=1)
    return candidate.replace(microsecond=0)


def random_time_at_hour(
    rng: random.Random, start: datetime, end: datetime, target_hour: int
) -> datetime:
    """A timestamp inside [start, end) whose UTC hour == ``target_hour``.

    Falls back to any time in the window if no day in the range contains that
    hour (shouldn't happen for windows >= 24h).
    """
    candidates: list[datetime] = []
    cursor = start.replace(minute=0, second=0, microsecond=0)
    while cursor < end:
        if cursor.hour == target_hour and start <= cursor < end:
            candidates.append(cursor)
        cursor += timedelta(hours=1)
    if not candidates:
        return random_time(rng, start, end)
    base = rng.choice(candidates)
    return base + timedelta(seconds=rng.uniform(0, 3600))


def iso_z(dt: datetime) -> str:
    """2026-09-05T14:22:31Z"""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def clf_time(dt: datetime) -> str:
    """05/Sep/2026:14:22:31 +0000  (Common Log Format)"""
    dt = dt.astimezone(timezone.utc)
    return f"{dt.day:02d}/{_MONTHS[dt.month - 1]}/{dt.year}:{dt:%H:%M:%S} +0000"
