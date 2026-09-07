"""Authentication log generator (sshd / sudo style).

Emits benign background auth traffic:
* mostly successful interactive logins by internal users from internal IPs,
* the occasional single mistyped password immediately followed by success,
* benign ``sudo`` invocations (from a safe command list - never the
  privilege-escalation keywords the detection rule looks for),
* session-close (logout) records.

Seeded attack bursts are added separately by ``simulation.attack_scenarios``.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

from ..common import internal_ip, iso_z, random_time
from ..schema import (
    EVENT_LOGIN,
    EVENT_LOGOUT,
    EVENT_SUDO,
    SOURCE_AUTH,
    STATUS_FAILURE,
    STATUS_SUCCESS,
    LogEvent,
)

HOSTNAME = "app01"

# Benign sudo commands - deliberately exclude every privilege-escalation keyword.
_BENIGN_SUDO_COMMANDS = [
    "/usr/bin/apt-get update",
    "/bin/systemctl restart nginx",
    "/bin/systemctl status postgresql",
    "/usr/bin/tail -f /var/log/syslog",
    "/usr/bin/journalctl -u sentrexa",
    "/bin/df -h",
]


def _pid(rng: random.Random) -> int:
    return rng.randint(1000, 32000)


def _port(rng: random.Random) -> int:
    return rng.randint(1024, 65535)


def _login_line(
    dt: datetime, ok: bool, user: str, ip: str, rng: random.Random,
    *, invalid_user: bool = False,
) -> str:
    verb = "Accepted" if ok else "Failed"
    who = f"invalid user {user}" if (invalid_user and not ok) else user
    return (
        f"{iso_z(dt)} {HOSTNAME} sshd[{_pid(rng)}]: {verb} password for {who} "
        f"from {ip} port {_port(rng)} ssh2"
    )


def _logout_line(dt: datetime, user: str, rng: random.Random) -> str:
    return (
        f"{iso_z(dt)} {HOSTNAME} sshd[{_pid(rng)}]: "
        f"pam_unix(sshd:session): session closed for user {user}"
    )


def _sudo_line(dt: datetime, user: str, command: str, rng: random.Random) -> str:
    return (
        f"{iso_z(dt)} {HOSTNAME} sudo:  {user} : TTY=pts/{rng.randint(0, 9)} ; "
        f"PWD=/home/{user} ; USER=root ; COMMAND={command}"
    )


def login_event(
    dt: datetime, *, ok: bool, user: str, ip: str, rng: random.Random,
    invalid_user: bool = False,
) -> LogEvent:
    return LogEvent(
        timestamp=dt,
        source_system=SOURCE_AUTH,
        source_ip=ip,
        username=user,
        event_type=EVENT_LOGIN,
        status=STATUS_SUCCESS if ok else STATUS_FAILURE,
        raw_message=_login_line(dt, ok, user, ip, rng, invalid_user=invalid_user),
    )


def logout_event(dt: datetime, *, user: str, ip: str, rng: random.Random) -> LogEvent:
    return LogEvent(
        timestamp=dt,
        source_system=SOURCE_AUTH,
        source_ip=ip,
        username=user,
        event_type=EVENT_LOGOUT,
        status=STATUS_SUCCESS,
        raw_message=_logout_line(dt, user, rng),
    )


def sudo_event(
    dt: datetime, *, user: str, command: str, ip: str, rng: random.Random, ok: bool = True,
) -> LogEvent:
    return LogEvent(
        timestamp=dt,
        source_system=SOURCE_AUTH,
        source_ip=ip,
        username=user,
        event_type=EVENT_SUDO,
        status=STATUS_SUCCESS if ok else STATUS_FAILURE,
        raw_message=_sudo_line(dt, user, command, rng),
    )


def generate_auth_events(
    rng: random.Random,
    *,
    count: int,
    start: datetime,
    end: datetime,
    users: list[str],
    admin_users: list[str],
) -> list[LogEvent]:
    """Return exactly ``count`` benign auth events spread across [start, end)."""
    events: list[LogEvent] = []
    sudo_capable = list(dict.fromkeys(users[:4] + admin_users))

    while len(events) < count:
        dt = random_time(rng, start, end)
        user = rng.choice(users)
        ip = internal_ip(rng)
        roll = rng.random()

        if roll < 0.72:
            events.append(login_event(dt, ok=True, user=user, ip=ip, rng=rng))
        elif roll < 0.82:
            # a fumbled password, then success 5-45s later
            events.append(login_event(dt, ok=False, user=user, ip=ip, rng=rng))
            events.append(
                login_event(
                    dt + timedelta(seconds=rng.uniform(5, 45)),
                    ok=True, user=user, ip=ip, rng=rng,
                )
            )
        elif roll < 0.90:
            events.append(logout_event(dt, user=user, ip=ip, rng=rng))
        else:
            events.append(
                sudo_event(
                    dt,
                    user=rng.choice(sudo_capable),
                    command=rng.choice(_BENIGN_SUDO_COMMANDS),
                    ip=ip,
                    rng=rng,
                )
            )
    return events[:count]
