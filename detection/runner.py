"""Detection cycle driver.

Selects the unprocessed ``logs_raw`` batch, runs every active rule over it, and
- when committing - marks those logs ``processed = true`` in the same
transaction and writes a ``detect`` row to ``detection_run_log``.

Phase 3 stops at ``Detection`` objects. Phase 4 turns them into alerts /
incidents; this module gains an ``alerts_generated`` count then.

Run:
    python -m detection.runner            # dry run: detect + print, touch nothing
    python -m detection.runner --commit   # persist the processed flag + run log
"""

from __future__ import annotations

import argparse
import time
from collections import Counter
from dataclasses import dataclass, field

from sqlalchemy import insert, update

from db.engine import session_scope
from db.models import DetectionRunLog, LogRaw

from .rules_engine import (
    Detection,
    load_active_rules,
    load_unprocessed_logs,
    run_rules,
)


@dataclass
class DetectionRunResult:
    run_id: int | None
    logs_scanned: int
    marked_processed: int
    detections: list[Detection] = field(default_factory=list)
    status: str = "success"
    dry_run: bool = True
    duration_ms: int = 0

    def by_rule_type(self) -> Counter:
        return Counter(d.rule_type for d in self.detections)


def run_detection(*, commit: bool = False, limit: int | None = None) -> DetectionRunResult:
    started = time.monotonic()
    with session_scope("rw") as s:
        rules = load_active_rules(s)
        logs = load_unprocessed_logs(s, limit=limit)
        detections = run_rules(rules, logs)

        marked = 0
        run_id = None
        if commit and logs:
            marked = s.execute(
                update(LogRaw)
                .where(LogRaw.log_id.in_([l.log_id for l in logs]))
                .values(processed=True)
            ).rowcount

        duration_ms = int((time.monotonic() - started) * 1000)
        if commit:
            run_id = s.execute(
                insert(DetectionRunLog)
                .values(
                    stage="detect",
                    logs_processed=len(logs),
                    alerts_generated=0,  # populated in Phase 4
                    status="success",
                    duration_ms=duration_ms,
                )
                .returning(DetectionRunLog.run_id)
            ).scalar_one()

    return DetectionRunResult(
        run_id=run_id,
        logs_scanned=len(logs),
        marked_processed=marked,
        detections=detections,
        dry_run=not commit,
        duration_ms=duration_ms,
    )


def _print(result: DetectionRunResult) -> None:
    mode = "DRY RUN" if result.dry_run else f"committed (run_id={result.run_id})"
    print(f"detection {mode}: scanned {result.logs_scanned} unprocessed logs, "
          f"{len(result.detections)} detection(s), {result.duration_ms} ms")
    for rule_type, n in sorted(result.by_rule_type().items()):
        print(f"  {rule_type:<22} {n}")
    for d in result.detections:
        who = d.source_ip or d.username or "-"
        print(f"    [{d.severity:<8}] {d.rule_type:<22} {who:<18} "
              f"{d.triggered_at:%Y-%m-%d %H:%M}  logs={len(d.log_ids)}  {d.dedup_key}")
    if not result.dry_run:
        print(f"  marked {result.marked_processed} logs processed")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run one detection cycle.")
    p.add_argument("--commit", action="store_true",
                   help="persist the processed flag and write a detection_run_log row")
    p.add_argument("--limit", type=int, default=None,
                   help="cap the number of unprocessed logs scanned")
    args = p.parse_args(argv)
    _print(run_detection(commit=args.commit, limit=args.limit))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
