"""Phase 5 tests: weekly report + dashboard data layer.

DB integration (auto-skips without a database). The dashboard's Streamlit UI is
verified manually (screenshot in the Phase 6 report); here we test the query
layer it sits on.
"""

from __future__ import annotations

import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytestmark = pytest.mark.db

END = datetime(2026, 9, 7, 12, 0, 0, tzinfo=timezone.utc)


def _seed_pipeline(cleanup_batch) -> str:
    """Ingest a crafted feed and run one committed detection cycle."""
    from detection.runner import run_detection
    from ingestion.load import ingest_feed

    batch = cleanup_batch(f"test-{uuid.uuid4()}")
    base = datetime(2026, 9, 3, 3, 0, 0, tzinfo=timezone.utc)
    lines = [
        '{"source_system":"auth","raw_message":"%s app01 sshd[%d]: Failed password for ariwan from 203.0.113.55 port %d ssh2"}'
        % ((base + timedelta(seconds=6 * i)).strftime("%Y-%m-%dT%H:%M:%SZ"), i, 5000 + i)
        for i in range(13)
    ]
    lines.append(
        '{"source_system":"auth","raw_message":"2026-09-03T02:30:00Z app01 sshd[1]: '
        'Accepted password for bthomas from 10.1.4.9 port 6000 ssh2"}'
    )
    lines.append(
        '{"source_system":"auth","raw_message":"2026-09-03T02:31:00Z app01 sudo:  '
        'bthomas : TTY=pts/0 ; PWD=/home/bthomas ; USER=root ; COMMAND=sudo su"}'
    )
    with tempfile.TemporaryDirectory() as td:
        feed = Path(td) / "f.ndjson"
        feed.write_text("\n".join(lines) + "\n", encoding="utf-8")
        ingest_feed(feed, batch_name=batch)
        run_detection(commit=True)
    return batch


class TestWeeklyReport:
    def test_report_renders_all_sections_with_data(
        self, clean_slate, cleanup_batch
    ) -> None:
        from reports.weekly_report import gather, render, write_report

        _seed_pipeline(cleanup_batch)

        ctx = gather(window_days=7, end=END)
        assert ctx["summary"]["alerts_total"] >= 3          # brute + off-hours + priv-esc
        assert ctx["summary"]["incidents_opened"] >= 2      # brute + priv-esc (high)
        assert {r["mitre_technique_id"] for r in ctx["by_technique"]}

        html = render(ctx)
        for section in [
            "Alerts by severity", "Alerts by MITRE technique", "Top alerts",
            "Open incidents", "Top offending source IPs", "Detection pipeline health",
        ]:
            assert section in html
        assert "Brute Force: Password Guessing" in html
        assert 'class="empty"' not in html or html.count('class="empty"') <= 1

        with tempfile.TemporaryDirectory() as td:
            path = write_report(out_dir=Path(td), window_days=7, end=END)
            assert path.exists() and path.stat().st_size > 2000

    def test_report_handles_an_empty_window(self, clean_slate) -> None:
        from reports.weekly_report import gather, render

        # window far in the past, nothing in it
        past = datetime(2020, 1, 8, tzinfo=timezone.utc)
        ctx = gather(window_days=7, end=past)
        assert ctx["summary"]["alerts_total"] == 0
        html = render(ctx)
        assert "No alerts in this period." in html
        assert "No open incidents" in html


class TestDashboardData:
    def test_query_helpers_return_expected_columns(
        self, clean_slate, cleanup_batch
    ) -> None:
        from dashboard import data

        _seed_pipeline(cleanup_batch)
        data.load_alerts.clear()
        data.kpis.clear()
        data.load_logs.clear()

        k = data.kpis()
        assert {"total_alerts", "open_incidents", "total_logs"} <= set(k)

        alerts = data.load_alerts(None, None, None, *data.default_window(30), 100)
        assert {"alert_id", "severity", "technique_name", "tactic"} <= set(alerts.columns)
        assert len(alerts) >= 3

        logs = data.load_logs("auth", "login", "failure", "203.0.113.55",
                              *data.default_window(30), 100)
        assert len(logs) == 13
        assert (logs["status"] == "failure").all()

    def test_alert_log_drilldown(self, clean_slate, cleanup_batch) -> None:
        from dashboard import data

        _seed_pipeline(cleanup_batch)
        data.load_alerts.clear()
        alerts = data.load_alerts(["high"], ["brute_force"], None,
                                  *data.default_window(30), 10)
        assert len(alerts) == 1
        logs = data.load_alert_logs(int(alerts.iloc[0]["alert_id"]))
        assert len(logs) == 13
