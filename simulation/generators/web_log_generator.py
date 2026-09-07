"""Web access log generator (nginx / Common Log Format style).

Emits benign HTTP traffic: normal application paths, mostly 2xx/3xx responses
from internal and known-external clients, with a realistic sprinkle of 404 /
401 / 500. Every line is one CLF record:

    IP - AUTHUSER [CLF-TIME] "METHOD PATH HTTP/1.1" CODE SIZE "REFERER" "UA"
"""

from __future__ import annotations

import random
from datetime import datetime

from ..common import clf_time, external_ip, internal_ip, random_time, stable_external_ips
from ..schema import (
    EVENT_HTTP_REQUEST,
    SOURCE_WEB,
    STATUS_ALLOWED,
    STATUS_BLOCKED,
    LogEvent,
)

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "curl/8.6.0",
    "python-requests/2.32.3",
]

# (method, path, weight) for benign requests
_BENIGN_REQUESTS = [
    ("GET", "/", 8),
    ("GET", "/dashboard", 6),
    ("GET", "/health", 5),
    ("GET", "/static/app.css", 4),
    ("GET", "/static/app.js", 4),
    ("GET", "/api/v1/alerts", 5),
    ("GET", "/api/v1/incidents", 4),
    ("POST", "/api/v1/search", 3),
    ("GET", "/favicon.ico", 2),
    ("POST", "/login", 3),
]
_BENIGN_METHODS, _BENIGN_PATHS, _BENIGN_WEIGHTS = zip(*[
    (m, p, w) for (m, p, w) in _BENIGN_REQUESTS
])


def _status_code(rng: random.Random, path: str) -> int:
    r = rng.random()
    if path == "/login":
        # most logins succeed; some bad passwords -> 401; rare redirect
        return 200 if r < 0.8 else (401 if r < 0.95 else 302)
    if r < 0.86:
        return 200
    if r < 0.93:
        return 304
    if r < 0.96:
        return 302
    if r < 0.985:
        return 404
    return 500


def _clf_line(
    ip: str, authuser: str | None, dt: datetime, method: str, path: str,
    code: int, size: int, referer: str, ua: str,
) -> str:
    who = authuser if authuser else "-"
    return (
        f'{ip} - {who} [{clf_time(dt)}] "{method} {path} HTTP/1.1" '
        f'{code} {size} "{referer}" "{ua}"'
    )


def http_event(
    *, ip: str, authuser: str | None, dt: datetime, method: str, path: str,
    code: int, rng: random.Random, referer: str = "-",
) -> LogEvent:
    size = 0 if code in (204, 304) else rng.randint(120, 18000)
    ua = rng.choice(_USER_AGENTS)
    status = STATUS_ALLOWED if code < 400 else STATUS_BLOCKED
    return LogEvent(
        timestamp=dt,
        source_system=SOURCE_WEB,
        source_ip=ip,
        username=authuser,
        event_type=EVENT_HTTP_REQUEST,
        status=status,
        raw_message=_clf_line(ip, authuser, dt, method, path, code, size, referer, ua),
    )


def generate_web_events(
    rng: random.Random,
    *,
    count: int,
    start: datetime,
    end: datetime,
    users: list[str],
) -> list[LogEvent]:
    """Return exactly ``count`` benign web events spread across [start, end)."""
    events: list[LogEvent] = []
    known_external = stable_external_ips(rng, 25)

    while len(events) < count:
        dt = random_time(rng, start, end)
        idx = rng.choices(range(len(_BENIGN_METHODS)), weights=_BENIGN_WEIGHTS, k=1)[0]
        method, path = _BENIGN_METHODS[idx], _BENIGN_PATHS[idx]
        code = _status_code(rng, path)

        # authenticated app calls carry a username; static/health are anonymous
        if path.startswith(("/api/", "/dashboard")) or path == "/login":
            authuser = rng.choice(users) if code < 400 else None
        else:
            authuser = None

        if rng.random() < 0.55:
            ip = internal_ip(rng)
        else:
            ip = rng.choice(known_external) if rng.random() < 0.8 else external_ip(rng)

        events.append(
            http_event(
                ip=ip, authuser=authuser, dt=dt, method=method, path=path,
                code=code, rng=rng,
            )
        )
    return events[:count]
