"""Weekly SOC summary report.

Renders a self-contained HTML page (Jinja2) from a 7-day window of alert /
incident / pipeline data, read through the least-privilege read-only role.

Run:
    python -m reports.weekly_report                       # last 7 days, -> reports/out/
    python -m reports.weekly_report --days 14 --end 2026-09-07T12:00:00Z
    python -m reports.weekly_report --out /tmp
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import text

from config.settings import PROJECT_ROOT
from db.engine import get_engine

TEMPLATE_DIR = PROJECT_ROOT / "reports" / "templates"
DEFAULT_OUT_DIR = PROJECT_ROOT / "reports" / "out"
TEMPLATE_NAME = "weekly_report.html.j2"


def _rows(conn, sql: str, params: dict) -> list[dict]:
    return [dict(m) for m in conn.execute(text(sql), params).mappings().all()]


def gather(*, window_days: int = 7, end: datetime | None = None) -> dict:
    end = (end or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start = end - timedelta(days=window_days)
    p = {"start": start, "end": end}

    with get_engine("ro").connect() as conn:
        summary_row = _rows(
            conn,
            """
            SELECT
              (SELECT count(*) FROM alerts WHERE triggered_at >= :start AND triggered_at < :end) AS alerts_total,
              (SELECT count(*) FROM alerts WHERE triggered_at >= :start AND triggered_at < :end AND status = 'New') AS alerts_new,
              (SELECT count(*) FROM alerts WHERE triggered_at >= :start AND triggered_at < :end AND severity IN ('high','critical')) AS alerts_high,
              (SELECT count(*) FROM incidents WHERE opened_at >= :start AND opened_at < :end) AS incidents_opened,
              (SELECT count(*) FROM incidents WHERE status <> 'Closed') AS incidents_open_now,
              (SELECT count(*) FROM logs_raw WHERE ingested_at >= :start AND ingested_at < :end) AS logs_ingested,
              (SELECT count(*) FROM rejected_records WHERE rejected_at >= :start AND rejected_at < :end) AS logs_rejected
            """,
            p,
        )[0]

        by_severity = _rows(
            conn,
            """
            SELECT severity, count(*) AS n FROM alerts
            WHERE triggered_at >= :start AND triggered_at < :end
            GROUP BY severity
            ORDER BY array_position(ARRAY['critical','high','medium','low'], severity)
            """,
            p,
        )
        by_technique = _rows(
            conn,
            """
            SELECT tactic, technique_name, mitre_technique_id, count(*) AS n
            FROM v_alert_enriched
            WHERE triggered_at >= :start AND triggered_at < :end
            GROUP BY tactic, technique_name, mitre_technique_id
            ORDER BY n DESC
            """,
            p,
        )
        top_alerts = _rows(
            conn,
            """
            SELECT triggered_at, severity, rule_name, technique_name,
                   host(source_ip) AS source_ip, username, alert_status
            FROM v_alert_enriched
            WHERE triggered_at >= :start AND triggered_at < :end
            ORDER BY array_position(ARRAY['critical','high','medium','low'], severity),
                     triggered_at DESC
            LIMIT 20
            """,
            p,
        )
        open_incidents = _rows(
            conn,
            """
            SELECT i.incident_id, a.severity, r.rule_name, i.opened_at,
                   i.assigned_to,
                   EXTRACT(EPOCH FROM (now() - i.opened_at))/3600.0 AS age_hours
            FROM incidents i
            JOIN alerts a          ON a.alert_id = i.alert_id
            JOIN detection_rules r ON r.rule_id = a.rule_id
            WHERE i.status <> 'Closed'
            ORDER BY i.opened_at
            """,
            p,
        )
        top_ips = _rows(
            conn,
            """
            SELECT host(source_ip) AS source_ip, count(*) AS alerts
            FROM alerts
            WHERE triggered_at >= :start AND triggered_at < :end AND source_ip IS NOT NULL
            GROUP BY source_ip ORDER BY alerts DESC LIMIT 10
            """,
            p,
        )
        top_users = _rows(
            conn,
            """
            SELECT username, count(*) AS alerts
            FROM alerts
            WHERE triggered_at >= :start AND triggered_at < :end AND username IS NOT NULL
            GROUP BY username ORDER BY alerts DESC LIMIT 10
            """,
            p,
        )
        runs = _rows(
            conn,
            """
            SELECT run_id, run_timestamp, stage, logs_processed, alerts_generated,
                   status, duration_ms
            FROM detection_run_log
            WHERE run_timestamp >= :start AND run_timestamp < :end
            ORDER BY run_timestamp DESC LIMIT 30
            """,
            p,
        )

    return {
        "period_start": start.isoformat(),
        "period_end": end.isoformat(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary_row,
        "by_severity": by_severity,
        "by_technique": by_technique,
        "top_alerts": top_alerts,
        "open_incidents": open_incidents,
        "top_ips": top_ips,
        "top_users": top_users,
        "runs": runs,
    }


def render(context: dict) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml", "j2"]),
    )
    return env.get_template(TEMPLATE_NAME).render(**context)


def write_report(
    *, out_dir: Path | None = None, window_days: int = 7, end: datetime | None = None
) -> Path:
    context = gather(window_days=window_days, end=end)
    html = render(context)
    out_dir = out_dir or DEFAULT_OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = context["period_end"][:10]
    path = out_dir / f"weekly_{stamp}.html"
    path.write_text(html, encoding="utf-8")
    return path


def _iso(text_: str) -> datetime:
    return datetime.fromisoformat(text_.replace("Z", "+00:00")).astimezone(timezone.utc)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Generate the weekly SOC summary report.")
    p.add_argument("--days", type=int, default=7)
    p.add_argument("--end", type=_iso, default=None, help="UTC window end (default: now)")
    p.add_argument("--out", type=Path, default=None)
    args = p.parse_args(argv)
    path = write_report(out_dir=args.out, window_days=args.days, end=args.end)
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
