"""Normalized log event schema.

This is the canonical shape every generator produces and every downstream stage
(ingestion, detection) reasons about. Its fields map 1:1 onto the ``logs_raw``
table defined in the spec (section 5a):

    timestamp | source_system | source_ip | username | event_type | status | raw_message

Design notes
------------
* ``timestamp`` is always timezone-aware UTC - the *event* time, parsed out of
  the raw log line (not the wall-clock time ingestion saw it).
* ``status`` uses a small source-independent vocabulary so detection rules do not
  need to know whether a record came from sshd, nginx, or a firewall.
* Generators emit both the structured ``LogEvent`` *and* a realistic
  single-line ``raw_message``. Only the raw line + a ``source_system`` routing
  hint are written to disk; Phase 2's parser must recover the structured fields
  from the raw line. The structured object is kept in-process as the test oracle.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone

# Source systems ----------------------------------------------------------------
SOURCE_AUTH = "auth"
SOURCE_WEB = "web"
SOURCE_FIREWALL = "firewall"
SOURCE_SYSTEMS: tuple[str, ...] = (SOURCE_AUTH, SOURCE_WEB, SOURCE_FIREWALL)

# Normalized status vocabulary ------------------------------------------------- #
STATUS_SUCCESS = "success"   # auth: login/sudo accepted
STATUS_FAILURE = "failure"   # auth: login/sudo rejected
STATUS_ALLOWED = "allowed"   # web: 2xx/3xx  | firewall: ACTION=ALLOW
STATUS_BLOCKED = "blocked"   # web: 4xx/5xx  | firewall: ACTION=DENY
STATUSES: tuple[str, ...] = (STATUS_SUCCESS, STATUS_FAILURE, STATUS_ALLOWED, STATUS_BLOCKED)

# Event types ---------------------------------------------------------------- #
EVENT_LOGIN = "login"
EVENT_LOGOUT = "logout"
EVENT_SUDO = "sudo"
EVENT_HTTP_REQUEST = "http_request"
EVENT_CONNECTION = "connection"
EVENT_TYPES: tuple[str, ...] = (
    EVENT_LOGIN,
    EVENT_LOGOUT,
    EVENT_SUDO,
    EVENT_HTTP_REQUEST,
    EVENT_CONNECTION,
)

# Which statuses are valid for which source, used by validate() and by the
# Phase 2 parser as a sanity check.
_VALID_STATUS_BY_SOURCE: dict[str, set[str]] = {
    SOURCE_AUTH: {STATUS_SUCCESS, STATUS_FAILURE},
    SOURCE_WEB: {STATUS_ALLOWED, STATUS_BLOCKED},
    SOURCE_FIREWALL: {STATUS_ALLOWED, STATUS_BLOCKED},
}


class LogEventError(ValueError):
    """Raised when a LogEvent fails structural validation."""


@dataclass(frozen=True, slots=True)
class LogEvent:
    timestamp: datetime          # tz-aware UTC, the event time
    source_system: str           # one of SOURCE_SYSTEMS
    source_ip: str               # IPv4 string
    username: str | None         # None for events with no principal (most firewall)
    event_type: str              # one of EVENT_TYPES
    status: str                  # one of STATUSES (constrained by source_system)
    raw_message: str             # realistic single-line log record

    # -- construction helpers ------------------------------------------------ #
    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if self.source_system not in SOURCE_SYSTEMS:
            raise LogEventError(f"unknown source_system: {self.source_system!r}")
        if self.event_type not in EVENT_TYPES:
            raise LogEventError(f"unknown event_type: {self.event_type!r}")
        if self.status not in STATUSES:
            raise LogEventError(f"unknown status: {self.status!r}")
        allowed = _VALID_STATUS_BY_SOURCE[self.source_system]
        if self.status not in allowed:
            raise LogEventError(
                f"status {self.status!r} invalid for source {self.source_system!r} "
                f"(expected one of {sorted(allowed)})"
            )
        if self.timestamp.tzinfo is None:
            raise LogEventError("timestamp must be timezone-aware")
        if self.timestamp.utcoffset() != timezone.utc.utcoffset(None):
            raise LogEventError("timestamp must be UTC")
        try:
            ipaddress.ip_address(self.source_ip)
        except ValueError as exc:
            raise LogEventError(f"invalid source_ip: {self.source_ip!r}") from exc
        if not self.raw_message or "\n" in self.raw_message:
            raise LogEventError("raw_message must be a non-empty single line")
        if self.username is not None and not self.username.strip():
            raise LogEventError("username, if present, must be non-empty")

    # -- serialization ----------------------------------------------------- #
    def disk_record(self) -> dict[str, str]:
        """The (deliberately minimal) shape written to the NDJSON feed on disk.

        Only a source routing hint and the raw line - Phase 2 recovers the rest.
        """
        return {"source_system": self.source_system, "raw_message": self.raw_message}

    def oracle_record(self) -> dict[str, str | None]:
        """The full structured event, used as ground truth in tests and manifests."""
        return {
            "timestamp": self.timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "source_system": self.source_system,
            "source_ip": self.source_ip,
            "username": self.username,
            "event_type": self.event_type,
            "status": self.status,
            "raw_message": self.raw_message,
        }

    def to_ndjson_line(self) -> str:
        return json.dumps(self.disk_record(), separators=(",", ":"), ensure_ascii=False)
