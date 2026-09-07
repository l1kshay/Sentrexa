"""Load a simulated log feed into PostgreSQL.

Reads an NDJSON feed (default: the newest one, via ``data/raw/_latest.json``),
parses each line with ``ingestion.parse``, and:

* inserts good rows into ``logs_raw`` (``processed = false``), skipping any whose
  ``dedup_hash`` already exists - so re-running on the same feed is a no-op;
* writes every unparseable line to ``rejected_records`` with the reason - never
  dropped, never fatal;
* records one ``detection_run_log`` row for the ingest stage.

Run:
    python -m ingestion.load                     # newest feed in data/raw/
    python -m ingestion.load path/to/feed.ndjson
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import insert
from sqlalchemy.dialects.postgresql import insert as pg_insert

from config.settings import settings
from db.engine import session_scope
from db.models import DetectionRunLog, LogRaw, RejectedRecord

from .parse import ParseError, parse_feed_line

_CHUNK = 1000


@dataclass
class IngestResult:
    source_file: str
    total_lines: int
    inserted: int
    duplicates: int
    rejected: int
    duration_ms: int
    run_id: int | None = None

    def summary(self) -> str:
        return (
            f"{self.source_file}: {self.total_lines} lines -> "
            f"{self.inserted} inserted, {self.duplicates} duplicate, "
            f"{self.rejected} quarantined ({self.duration_ms} ms)"
        )


def _sha(*parts: object) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(str(p).encode("utf-8"))
        h.update(b"\x1f")
    return h.hexdigest()


def _resolve_latest(raw_dir: Path) -> Path:
    pointer = raw_dir / "_latest.json"
    if not pointer.exists():
        sys.exit(f"ERROR: no feed given and {pointer} not found. Run the simulator first.")
    feed_name = json.loads(pointer.read_text(encoding="utf-8"))["feed"]
    return raw_dir / feed_name


def ingest_feed(feed_path: Path, *, batch_name: str | None = None) -> IngestResult:
    started = time.monotonic()
    batch = batch_name or feed_path.name
    lines = feed_path.read_text(encoding="utf-8").splitlines()

    good_rows: list[dict] = []
    reject_rows: list[dict] = []
    for line_no, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            event = parse_feed_line(line)
        except ParseError as exc:
            reject_rows.append(
                {
                    "stage": "ingestion",
                    "source_file": batch,
                    "line_number": line_no,
                    "raw_line": line,
                    "reason": exc.reason,
                    "dedup_hash": _sha(batch, line_no, line),
                }
            )
            continue
        good_rows.append(
            {
                "timestamp": event.timestamp,
                "source_system": event.source_system,
                "source_ip": event.source_ip,
                "username": event.username,
                "event_type": event.event_type,
                "status": event.status,
                "raw_message": event.raw_message,
                "processed": False,
                "ingest_batch": batch,
                "dedup_hash": _sha(batch, line_no, event.raw_message),
            }
        )

    inserted = 0
    with session_scope("rw") as s:
        for i in range(0, len(good_rows), _CHUNK):
            chunk = good_rows[i : i + _CHUNK]
            stmt = (
                pg_insert(LogRaw)
                .values(chunk)
                .on_conflict_do_nothing(index_elements=["dedup_hash"])
                .returning(LogRaw.log_id)
            )
            inserted += len(s.execute(stmt).fetchall())

        for i in range(0, len(reject_rows), _CHUNK):
            chunk = reject_rows[i : i + _CHUNK]
            s.execute(
                pg_insert(RejectedRecord)
                .values(chunk)
                .on_conflict_do_nothing(index_elements=["dedup_hash"])
            )

        duration_ms = int((time.monotonic() - started) * 1000)
        run = s.execute(
            insert(DetectionRunLog)
            .values(
                stage="ingest",
                logs_processed=inserted,
                alerts_generated=0,
                status="partial" if reject_rows else "success",
                error_message=(
                    f"{len(reject_rows)} line(s) quarantined" if reject_rows else None
                ),
                duration_ms=duration_ms,
            )
            .returning(DetectionRunLog.run_id)
        ).scalar_one()

    return IngestResult(
        source_file=batch,
        total_lines=len(lines),
        inserted=inserted,
        duplicates=len(good_rows) - inserted,
        rejected=len(reject_rows),
        duration_ms=duration_ms,
        run_id=run,
    )


def ingest_latest(raw_dir: Path | None = None) -> IngestResult:
    raw_dir = raw_dir or settings.simulation.output_dir
    return ingest_feed(_resolve_latest(raw_dir))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Ingest a simulated log feed into PostgreSQL.")
    p.add_argument("feed", nargs="?", type=Path, help="feed .ndjson (default: newest)")
    args = p.parse_args(argv)

    result = ingest_feed(args.feed) if args.feed else ingest_latest()
    print(result.summary())
    print(f"detection_run_log.run_id = {result.run_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
