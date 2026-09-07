"""Read-only data access for the Streamlit dashboard.

Every query is parameterized and runs through the least-privilege ``ro`` engine.
Results are pandas DataFrames, cached briefly so re-renders don't hammer the DB.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd
import streamlit as st
from sqlalchemy import text

from db.engine import get_engine

_CACHE_TTL = 60  # seconds


def _engine():
    return get_engine("ro")


def _df(sql: str, params: dict | None = None) -> pd.DataFrame:
    with _engine().connect() as conn:
        return pd.read_sql_query(text(sql), conn, params=params or {})


# --------------------------------------------------------------------------- #
# Headline numbers
# --------------------------------------------------------------------------- #
@st.cache_data(ttl=_CACHE_TTL)
def kpis() -> dict:
    row = _df(
        """
        SELECT
          (SELECT count(*) FROM alerts)                                   AS total_alerts,
          (SELECT count(*) FROM alerts WHERE status = 'New')              AS new_alerts,
          (SELECT count(*) FROM alerts WHERE severity IN ('high','critical')) AS high_alerts,
          (SELECT count(*) FROM incidents WHERE status <> 'Closed')       AS open_incidents,
          (SELECT count(*) FROM incidents)                               AS total_incidents,
          (SELECT count(*) FROM logs_raw)                                AS total_logs,
          (SELECT count(*) FROM rejected_records)                        AS rejected_logs
        """
    ).iloc[0]
    return row.to_dict()


# --------------------------------------------------------------------------- #
# Alert feed
# --------------------------------------------------------------------------- #
@st.cache_data(ttl=_CACHE_TTL)
def load_alerts(
    severities: list[str] | None,
    rule_types: list[str] | None,
    statuses: list[str] | None,
    start: datetime | None,
    end: datetime | None,
    limit: int = 500,
) -> pd.DataFrame:
    clauses = ["1=1"]
    params: dict = {"limit": int(limit)}
    if severities:
        clauses.append("severity = ANY(:sev)")
        params["sev"] = list(severities)
    if rule_types:
        clauses.append("rule_type = ANY(:rt)")
        params["rt"] = list(rule_types)
    if statuses:
        clauses.append("alert_status = ANY(:st)")
        params["st"] = list(statuses)
    if start:
        clauses.append("triggered_at >= :start")
        params["start"] = start
    if end:
        clauses.append("triggered_at < :end")
        params["end"] = end

    return _df(
        f"""
        SELECT alert_id, triggered_at, severity, alert_status, rule_name, rule_type,
               mitre_technique_id, technique_name, tactic,
               host(source_ip) AS source_ip, username,
               incident_id, incident_status
        FROM v_alert_enriched
        WHERE {' AND '.join(clauses)}
        ORDER BY triggered_at DESC
        LIMIT :limit
        """,
        params,
    )


@st.cache_data(ttl=_CACHE_TTL)
def load_alert_logs(alert_id: int) -> pd.DataFrame:
    return _df(
        """
        SELECT g.log_id, g."timestamp", g.source_system, g.event_type, g.status,
               host(g.source_ip) AS source_ip, g.username, g.raw_message
        FROM alert_log_links l
        JOIN logs_raw g ON g.log_id = l.log_id
        WHERE l.alert_id = :aid
        ORDER BY g."timestamp"
        """,
        {"aid": int(alert_id)},
    )


# --------------------------------------------------------------------------- #
# Incident board
# --------------------------------------------------------------------------- #
@st.cache_data(ttl=_CACHE_TTL)
def load_incidents(statuses: list[str] | None = None) -> pd.DataFrame:
    clauses = ["i.incident_id IS NOT NULL"]
    params: dict = {}
    if statuses:
        clauses.append("i.status = ANY(:st)")
        params["st"] = list(statuses)
    return _df(
        f"""
        SELECT i.incident_id, i.status AS incident_status, i.opened_at, i.closed_at,
               i.assigned_to, i.resolution_notes,
               a.alert_id, a.severity, a.triggered_at, a.status AS alert_status,
               r.rule_name, r.rule_type, m.technique_name, m.tactic,
               host(a.source_ip) AS source_ip, a.username,
               EXTRACT(EPOCH FROM (COALESCE(i.closed_at, now()) - i.opened_at))/3600.0
                   AS age_hours
        FROM incidents i
        JOIN alerts a           ON a.alert_id = i.alert_id
        JOIN detection_rules r  ON r.rule_id = a.rule_id
        JOIN mitre_techniques m ON m.technique_id = r.mitre_technique_id
        WHERE {' AND '.join(clauses)}
        ORDER BY i.opened_at DESC
        """,
        params,
    )


# --------------------------------------------------------------------------- #
# Log search
# --------------------------------------------------------------------------- #
@st.cache_data(ttl=_CACHE_TTL)
def load_logs(
    source_system: str | None,
    event_type: str | None,
    status: str | None,
    needle: str | None,
    start: datetime | None,
    end: datetime | None,
    limit: int = 500,
) -> pd.DataFrame:
    clauses = ["1=1"]
    params: dict = {"limit": int(limit)}
    if source_system and source_system != "(any)":
        clauses.append("source_system = :src")
        params["src"] = source_system
    if event_type and event_type != "(any)":
        clauses.append("event_type = :et")
        params["et"] = event_type
    if status and status != "(any)":
        clauses.append("status = :stt")
        params["stt"] = status
    if needle:
        clauses.append("(raw_message ILIKE :needle OR username ILIKE :needle "
                       "OR host(source_ip) ILIKE :needle)")
        params["needle"] = f"%{needle}%"
    if start:
        clauses.append('"timestamp" >= :start')
        params["start"] = start
    if end:
        clauses.append('"timestamp" < :end')
        params["end"] = end

    return _df(
        f"""
        SELECT log_id, "timestamp", source_system, event_type, status,
               host(source_ip) AS source_ip, username, raw_message, processed
        FROM logs_raw
        WHERE {' AND '.join(clauses)}
        ORDER BY "timestamp" DESC
        LIMIT :limit
        """,
        params,
    )


# --------------------------------------------------------------------------- #
# Analytics
# --------------------------------------------------------------------------- #
@st.cache_data(ttl=_CACHE_TTL)
def alerts_by_severity() -> pd.DataFrame:
    return _df(
        "SELECT severity, count(*) AS n FROM alerts GROUP BY severity ORDER BY n DESC"
    )


@st.cache_data(ttl=_CACHE_TTL)
def alerts_by_tactic() -> pd.DataFrame:
    return _df(
        """
        SELECT tactic, technique_name, count(*) AS n
        FROM v_alert_enriched
        GROUP BY tactic, technique_name
        ORDER BY n DESC
        """
    )


@st.cache_data(ttl=_CACHE_TTL)
def alerts_over_time() -> pd.DataFrame:
    return _df(
        """
        SELECT date_trunc('day', triggered_at)::date AS day, severity, count(*) AS n
        FROM alerts
        GROUP BY 1, 2
        ORDER BY 1
        """
    )


@st.cache_data(ttl=_CACHE_TTL)
def top_source_ips(limit: int = 10) -> pd.DataFrame:
    return _df(
        """
        SELECT host(source_ip) AS source_ip, count(*) AS alerts
        FROM alerts
        WHERE source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY alerts DESC
        LIMIT :limit
        """,
        {"limit": int(limit)},
    )


@st.cache_data(ttl=_CACHE_TTL)
def top_usernames(limit: int = 10) -> pd.DataFrame:
    return _df(
        """
        SELECT username, count(*) AS alerts
        FROM alerts
        WHERE username IS NOT NULL
        GROUP BY username
        ORDER BY alerts DESC
        LIMIT :limit
        """,
        {"limit": int(limit)},
    )


@st.cache_data(ttl=_CACHE_TTL)
def run_log(limit: int = 50) -> pd.DataFrame:
    return _df(
        """
        SELECT run_id, run_timestamp, stage, logs_processed, alerts_generated,
               status, error_message, duration_ms
        FROM detection_run_log
        ORDER BY run_timestamp DESC
        LIMIT :limit
        """,
        {"limit": int(limit)},
    )


def default_window(days: int = 7) -> tuple[datetime, datetime]:
    end = datetime.now(timezone.utc)
    return end - timedelta(days=days), end
