"""Parse raw simulated log lines into normalized ``LogEvent`` records.

Two stages, each with its own failure mode:

1. ``load_feed_line`` - turn one NDJSON feed line into (source_system, raw_message).
   Fails if the line is not a JSON object, is missing/blank ``source_system`` or
   ``raw_message``, or names an unknown source.
2. ``parse_raw_message`` - apply that source's grammar to the raw line and return
   a validated ``LogEvent``. Fails if no grammar matches or the reconstructed
   event fails ``LogEvent.validate()``.

Anything that fails raises ``ParseError`` carrying a short ``reason``; ingestion
(``ingestion/load.py``) catches it and quarantines the line instead of crashing.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from simulation.schema import (
    EVENT_CONNECTION,
    EVENT_HTTP_REQUEST,
    EVENT_LOGIN,
    EVENT_LOGOUT,
    EVENT_SUDO,
    SOURCE_AUTH,
    SOURCE_FIREWALL,
    SOURCE_SYSTEMS,
    SOURCE_WEB,
    STATUS_ALLOWED,
    STATUS_BLOCKED,
    STATUS_FAILURE,
    STATUS_SUCCESS,
    LogEvent,
    LogEventError,
)


class ParseError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class RawLine:
    source_system: str
    raw_message: str


# --------------------------------------------------------------------------- #
# Stage 1: feed line -> RawLine
# --------------------------------------------------------------------------- #
def load_feed_line(line: str) -> RawLine:
    line = line.rstrip("\n")
    if not line.strip():
        raise ParseError("empty line")
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ParseError(f"not valid JSON: {exc.msg}") from exc
    if not isinstance(obj, dict):
        raise ParseError("JSON is not an object")

    source = obj.get("source_system")
    raw = obj.get("raw_message")
    if not source or not isinstance(source, str):
        raise ParseError("missing or blank source_system")
    if source not in SOURCE_SYSTEMS:
        raise ParseError(f"unknown source_system: {source!r}")
    if not raw or not isinstance(raw, str) or not raw.strip():
        raise ParseError("missing or blank raw_message")
    return RawLine(source_system=source, raw_message=raw)


# --------------------------------------------------------------------------- #
# Timestamp helpers
# --------------------------------------------------------------------------- #
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


def _iso_z(text: str) -> datetime:
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ParseError(f"bad ISO timestamp: {text!r}") from exc


def _clf_time(text: str) -> datetime:
    # 05/Sep/2026:14:22:31 +0000
    m = re.match(
        r"^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})$", text
    )
    if not m or m.group(2) not in _MONTHS:
        raise ParseError(f"bad CLF timestamp: {text!r}")
    day, mon, year, hh, mm, ss, tz = m.groups()
    offset_min = (1 if tz[0] == "+" else -1) * (int(tz[1:3]) * 60 + int(tz[3:5]))
    dt = datetime(int(year), _MONTHS[mon], int(day), int(hh), int(mm), int(ss),
                  tzinfo=timezone.utc)
    return dt - _tzdelta(offset_min)


def _tzdelta(minutes: int):
    from datetime import timedelta

    return timedelta(minutes=minutes)


# --------------------------------------------------------------------------- #
# Stage 2: grammars
# --------------------------------------------------------------------------- #
_ISO = r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)"

_AUTH_LOGIN = re.compile(
    rf"^{_ISO} \S+ sshd\[\d+\]: (?P<verb>Accepted|Failed) password for "
    rf"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+ ssh2$"
)
_AUTH_LOGOUT = re.compile(
    rf"^{_ISO} \S+ sshd\[\d+\]: pam_unix\(sshd:session\): "
    rf"session closed for user (?P<user>\S+)$"
)
_AUTH_SUDO = re.compile(
    rf"^{_ISO} \S+ sudo:\s+(?P<user>\S+) : TTY=\S+ ; PWD=\S+ ; "
    rf"USER=\S+ ; COMMAND=(?P<cmd>.+)$"
)
_WEB_CLF = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<authuser>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) HTTP/\d\.\d" '
    r'(?P<code>\d{3}) (?P<size>\d+|-) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"$'
)
_FW = re.compile(
    rf"^{_ISO} \S+ ACTION=(?P<action>ALLOW|DENY) PROTO=(?P<proto>\S+) "
    rf"SRC=(?P<src>\S+) DST=(?P<dst>\S+) SPT=(?P<spt>\d+) DPT=(?P<dpt>\d+)$"
)


def _parse_auth(raw: str) -> LogEvent:
    if m := _AUTH_LOGIN.match(raw):
        ok = m.group("verb") == "Accepted"
        return LogEvent(
            timestamp=_iso_z(m.group("ts")),
            source_system=SOURCE_AUTH,
            source_ip=m.group("ip"),
            username=m.group("user"),
            event_type=EVENT_LOGIN,
            status=STATUS_SUCCESS if ok else STATUS_FAILURE,
            raw_message=raw,
        )
    if m := _AUTH_LOGOUT.match(raw):
        return LogEvent(
            timestamp=_iso_z(m.group("ts")),
            source_system=SOURCE_AUTH,
            source_ip=None,
            username=m.group("user"),
            event_type=EVENT_LOGOUT,
            status=STATUS_SUCCESS,
            raw_message=raw,
        )
    if m := _AUTH_SUDO.match(raw):
        return LogEvent(
            timestamp=_iso_z(m.group("ts")),
            source_system=SOURCE_AUTH,
            source_ip=None,
            username=m.group("user"),
            event_type=EVENT_SUDO,
            status=STATUS_SUCCESS,
            raw_message=raw,
        )
    raise ParseError("unrecognized auth line grammar")


def _parse_web(raw: str) -> LogEvent:
    m = _WEB_CLF.match(raw)
    if not m:
        raise ParseError("unrecognized web line grammar")
    code = int(m.group("code"))
    authuser = m.group("authuser")
    return LogEvent(
        timestamp=_clf_time(m.group("ts")),
        source_system=SOURCE_WEB,
        source_ip=m.group("ip"),
        username=None if authuser == "-" else authuser,
        event_type=EVENT_HTTP_REQUEST,
        status=STATUS_ALLOWED if code < 400 else STATUS_BLOCKED,
        raw_message=raw,
    )


def _parse_firewall(raw: str) -> LogEvent:
    m = _FW.match(raw)
    if not m:
        raise ParseError("unrecognized firewall line grammar")
    return LogEvent(
        timestamp=_iso_z(m.group("ts")),
        source_system=SOURCE_FIREWALL,
        source_ip=m.group("src"),
        username=None,
        event_type=EVENT_CONNECTION,
        status=STATUS_ALLOWED if m.group("action") == "ALLOW" else STATUS_BLOCKED,
        raw_message=raw,
    )


_DISPATCH = {
    SOURCE_AUTH: _parse_auth,
    SOURCE_WEB: _parse_web,
    SOURCE_FIREWALL: _parse_firewall,
}


def parse_raw_message(source_system: str, raw_message: str) -> LogEvent:
    parser = _DISPATCH.get(source_system)
    if parser is None:
        raise ParseError(f"no parser for source_system {source_system!r}")
    try:
        return parser(raw_message)
    except LogEventError as exc:
        raise ParseError(f"reconstructed event invalid: {exc}") from exc


def parse_feed_line(line: str) -> LogEvent:
    rl = load_feed_line(line)
    return parse_raw_message(rl.source_system, rl.raw_message)
