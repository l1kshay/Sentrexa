"""Firewall log generator (iptables / pf key=value style).

Emits benign perimeter traffic: internal hosts reaching servers on 80/443/22
(ALLOW), plus low-volume background DENY noise from external scanners hitting
closed ports. Firewall records have no principal, so ``username`` is always None.

    ISO-TIME HOST ACTION=ALLOW|DENY PROTO=TCP|UDP SRC=.. DST=.. SPT=.. DPT=..
"""

from __future__ import annotations

import random
from datetime import datetime

from ..common import external_ip, internal_ip, iso_z, random_time
from ..schema import (
    EVENT_CONNECTION,
    SOURCE_FIREWALL,
    STATUS_ALLOWED,
    STATUS_BLOCKED,
    LogEvent,
)

HOSTNAME = "fw01"
_COMMON_DEST_PORTS = [443, 443, 443, 80, 22, 5432, 53]
_SCAN_DEST_PORTS = [23, 445, 3389, 8080, 21, 3306, 1433, 6379]


def _fw_line(
    dt: datetime, action: str, proto: str, src: str, dst: str, spt: int, dpt: int,
) -> str:
    return (
        f"{iso_z(dt)} {HOSTNAME} ACTION={action} PROTO={proto} "
        f"SRC={src} DST={dst} SPT={spt} DPT={dpt}"
    )


def firewall_event(
    *, dt: datetime, allow: bool, proto: str, src: str, dst: str, spt: int, dpt: int,
) -> LogEvent:
    return LogEvent(
        timestamp=dt,
        source_system=SOURCE_FIREWALL,
        source_ip=src,
        username=None,
        event_type=EVENT_CONNECTION,
        status=STATUS_ALLOWED if allow else STATUS_BLOCKED,
        raw_message=_fw_line(dt, "ALLOW" if allow else "DENY", proto, src, dst, spt, dpt),
    )


def generate_firewall_events(
    rng: random.Random,
    *,
    count: int,
    start: datetime,
    end: datetime,
) -> list[LogEvent]:
    """Return exactly ``count`` benign firewall events spread across [start, end)."""
    events: list[LogEvent] = []

    while len(events) < count:
        dt = random_time(rng, start, end)
        if rng.random() < 0.8:
            # internal host -> server, allowed
            events.append(
                firewall_event(
                    dt=dt, allow=True, proto="TCP",
                    src=internal_ip(rng), dst=internal_ip(rng, server=True),
                    spt=rng.randint(1024, 65535), dpt=rng.choice(_COMMON_DEST_PORTS),
                )
            )
        else:
            # external scanner -> closed port, denied
            events.append(
                firewall_event(
                    dt=dt, allow=False,
                    proto=rng.choice(["TCP", "TCP", "UDP"]),
                    src=external_ip(rng), dst=internal_ip(rng, server=True),
                    spt=rng.randint(1024, 65535), dpt=rng.choice(_SCAN_DEST_PORTS),
                )
            )
    return events[:count]
