"""Phase 2 tests: parsing + ingestion.

Parser tests run with no database. The DB integration tests use an admin engine
to set up and tear down (the app's rw role has no DELETE), and skip cleanly if
no database is reachable.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import text

from config.settings import settings
from ingestion.load import ingest_feed
from ingestion.parse import (
    ParseError,
    load_feed_line,
    parse_feed_line,
    parse_raw_message,
)
from simulation.attack_scenarios import build_all_scenarios
from simulation.common import make_rng, window
from simulation.generators.auth_log_generator import generate_auth_events
from simulation.generators.firewall_log_generator import generate_firewall_events
from simulation.generators.web_log_generator import generate_web_events

SIM = settings.simulation
END = datetime(2026, 9, 7, 12, 0, 0, tzinfo=timezone.utc)

_FIELDS = (
    "timestamp", "source_system", "source_ip", "username",
    "event_type", "status", "raw_message",
)


def _sample_events(n_each: int = 400):
    start, end = window(END, 168)
    rng = make_rng(1337)
    evs = generate_auth_events(
        rng, count=n_each, start=start, end=end,
        users=SIM.internal_users, admin_users=SIM.admin_users,
    )
    evs += generate_web_events(rng, count=n_each, start=start, end=end, users=SIM.internal_users)
    evs += generate_firewall_events(rng, count=n_each, start=start, end=end)
    for sc in build_all_scenarios(rng, start, end, SIM):
        evs += sc.events
    return evs


# --------------------------------------------------------------------------- #
# Parser: every generated line round-trips to its exact structured form
# --------------------------------------------------------------------------- #
class TestParserRoundTrip:
    def test_all_generated_lines_recover_exact_fields(self) -> None:
        events = _sample_events()
        assert len(events) > 1000
        for e in events:
            parsed = parse_raw_message(e.source_system, e.raw_message)
            for f in _FIELDS:
                assert getattr(parsed, f) == getattr(e, f), (f, e.raw_message)

    def test_disk_record_round_trips_through_feed_line(self) -> None:
        for e in _sample_events(120):
            assert parse_feed_line(e.to_ndjson_line()).raw_message == e.raw_message

    def test_invalid_user_auth_line(self) -> None:
        raw = "2026-09-05T02:03:04Z app01 sshd[42]: Failed password for invalid user root from 203.0.113.9 port 5000 ssh2"
        ev = parse_raw_message("auth", raw)
        assert ev.username == "root"
        assert ev.status == "failure"
        assert ev.source_ip == "203.0.113.9"

    def test_clf_timezone_offset_is_converted_to_utc(self) -> None:
        raw = ('198.51.100.7 - - [05/Sep/2026:12:30:00 +0530] '
               '"GET /health HTTP/1.1" 200 12 "-" "curl/8.6.0"')
        ev = parse_raw_message("web", raw)
        assert ev.timestamp == datetime(2026, 9, 5, 7, 0, 0, tzinfo=timezone.utc)

    def test_sudo_and_logout_lines_have_no_ip(self) -> None:
        sudo = parse_raw_message(
            "auth",
            "2026-09-05T03:00:00Z app01 sudo:  epatel : TTY=pts/0 ; PWD=/home/epatel ; USER=root ; COMMAND=sudo su",
        )
        out = parse_raw_message(
            "auth",
            "2026-09-05T03:05:00Z app01 sshd[9]: pam_unix(sshd:session): session closed for user epatel",
        )
        assert sudo.source_ip is None and sudo.event_type == "sudo"
        assert out.source_ip is None and out.event_type == "logout"


# --------------------------------------------------------------------------- #
# Parser: bad input is rejected with a reason (never returns garbage)
# --------------------------------------------------------------------------- #
class TestParserRejections:
    @pytest.mark.parametrize(
        "line, needle",
        [
            ("not json at all", "not valid JSON"),
            ('["auth", "x"]', "not an object"),
            ('{"raw_message": "x"}', "source_system"),
            ('{"source_system": "weather", "raw_message": "x"}', "unknown source_system"),
            ('{"source_system": "auth", "raw_message": ""}', "raw_message"),
            ('{"source_system": "auth"}', "raw_message"),
        ],
    )
    def test_load_feed_line_rejections(self, line: str, needle: str) -> None:
        with pytest.raises(ParseError) as ei:
            load_feed_line(line)
        assert needle in str(ei.value)

    @pytest.mark.parametrize(
        "source, raw",
        [
            ("auth", "2026-09-05T03:00:00Z app01 sshd[1]: something unexpected happened"),
            ("web", "this is not a CLF line"),
            ("firewall", "2026-09-05T03:00:00Z fw01 ACTION=MAYBE SRC=1.2.3.4"),
        ],
    )
    def test_unrecognized_grammar_rejected(self, source: str, raw: str) -> None:
        with pytest.raises(ParseError):
            parse_raw_message(source, raw)

    def test_bad_timestamp_rejected(self) -> None:
        with pytest.raises(ParseError):
            parse_raw_message(
                "firewall",
                "2026-13-99T99:99:99Z fw01 ACTION=ALLOW PROTO=TCP SRC=10.0.0.1 "
                "DST=10.0.0.2 SPT=1 DPT=2",
            )


# --------------------------------------------------------------------------- #
# Ingestion (DB integration - skips without a database)
# --------------------------------------------------------------------------- #
_GOOD_LINES = [
    '{"source_system":"auth","raw_message":"2026-09-05T02:10:00Z app01 sshd[1]: Accepted password for ariwan from 10.1.4.7 port 22000 ssh2"}',
    '{"source_system":"auth","raw_message":"2026-09-05T02:11:00Z app01 sshd[2]: Failed password for bthomas from 203.0.113.5 port 4000 ssh2"}',
    '{"source_system":"web","raw_message":"10.1.4.9 - ariwan [05/Sep/2026:02:12:00 +0000] \\"GET /dashboard HTTP/1.1\\" 200 900 \\"-\\" \\"curl/8.6.0\\""}',
    '{"source_system":"firewall","raw_message":"2026-09-05T02:13:00Z fw01 ACTION=DENY PROTO=TCP SRC=203.0.113.5 DST=10.1.0.5 SPT=4000 DPT=22"}',
]
_BAD_LINES = [
    "not json",
    '{"source_system":"auth"}',
    '{"source_system":"weather","raw_message":"x"}',
    '{"source_system":"auth","raw_message":"2026-09-05T02:00:00Z app01 sshd[1]: gibberish"}',
]


@pytest.fixture
def feed_file(tmp_path):
    def _write(lines: list[str]) -> "object":
        p = tmp_path / "feed.ndjson"
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return p

    return _write


@pytest.mark.db
class TestIngestion:
    def test_good_lines_land_in_logs_raw_bad_lines_quarantined(
        self, admin_engine, cleanup_batch, feed_file
    ) -> None:
        batch = cleanup_batch(f"test-{uuid.uuid4()}")
        path = feed_file(_GOOD_LINES + _BAD_LINES)

        res = ingest_feed(path, batch_name=batch)
        assert res.inserted == len(_GOOD_LINES)
        assert res.rejected == len(_BAD_LINES)

        with admin_engine.connect() as conn:
            rows = conn.execute(
                text('SELECT source_system, event_type, status, source_ip, '
                     'username, processed FROM logs_raw WHERE ingest_batch = :b '
                     'ORDER BY "timestamp"'),
                {"b": batch},
            ).all()
            rejects = conn.execute(
                text("SELECT reason FROM rejected_records WHERE source_file = :b"),
                {"b": batch},
            ).scalars().all()

        assert len(rows) == 4
        assert rows[0].source_system == "auth" and rows[0].status == "success"
        assert rows[2].source_system == "web" and rows[2].username == "ariwan"
        assert all(r.processed is False for r in rows)
        assert len(rejects) == len(_BAD_LINES)

    def test_reingesting_same_feed_creates_no_duplicates(
        self, admin_engine, cleanup_batch, feed_file
    ) -> None:
        batch = cleanup_batch(f"test-{uuid.uuid4()}")
        path = feed_file(_GOOD_LINES + _BAD_LINES)

        first = ingest_feed(path, batch_name=batch)
        second = ingest_feed(path, batch_name=batch)

        assert first.inserted == len(_GOOD_LINES)
        assert second.inserted == 0
        assert second.duplicates == len(_GOOD_LINES)

        with admin_engine.connect() as conn:
            n_logs = conn.execute(
                text("SELECT count(*) FROM logs_raw WHERE ingest_batch = :b"), {"b": batch}
            ).scalar_one()
            n_rej = conn.execute(
                text("SELECT count(*) FROM rejected_records WHERE source_file = :b"),
                {"b": batch},
            ).scalar_one()
        assert n_logs == len(_GOOD_LINES)
        assert n_rej == len(_BAD_LINES)

    def test_ingest_writes_a_run_log_row(
        self, admin_engine, cleanup_batch, feed_file
    ) -> None:
        batch = cleanup_batch(f"test-{uuid.uuid4()}")
        res = ingest_feed(feed_file(_GOOD_LINES), batch_name=batch)
        with admin_engine.connect() as conn:
            row = conn.execute(
                text("SELECT stage, logs_processed, status FROM detection_run_log "
                     "WHERE run_id = :r"),
                {"r": res.run_id},
            ).one()
        assert row.stage == "ingest"
        assert row.logs_processed == len(_GOOD_LINES)
        assert row.status == "success"
