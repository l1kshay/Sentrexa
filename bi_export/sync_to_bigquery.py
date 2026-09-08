"""Incremental PostgreSQL -> BigQuery sync.

Reads only (via the ``sentrexa_ro`` role) from PostgreSQL and MERGEs into the
BigQuery star schema. The last-synced watermark lives in ``analytics._sync_state``
in BigQuery, so this job never writes to the operational database.

Per target:
* ``dim_mitre_techniques`` / ``dim_detection_rules`` - full upsert each run (tiny).
* ``fact_alerts`` - rows whose GREATEST(alert.updated_at, incident.updated_at)
  is newer than the watermark; MERGE on ``alert_id``.
* ``fact_logs_daily`` - daily counts recomputed for any date that received logs
  since the watermark; MERGE on ``(log_date, source_system, event_type, status)``.

Every MERGE is keyed on a natural key, so re-running is idempotent - no
duplicate rows.

Run:
    python -m bi_export.sync_to_bigquery            # incremental
    python -m bi_export.sync_to_bigquery --full     # ignore the watermark
"""

from __future__ import annotations

import argparse
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import pandas as pd
from google.cloud import bigquery
from sqlalchemy import text

from bi_export.client import bigquery_client, table_ref
from bi_export.schema.bigquery_schema import MERGE_KEYS, SYNC_STATE, TABLES
from db.engine import get_engine

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass
class TableResult:
    target: str
    rows: int
    watermark_after: datetime


@dataclass
class SyncResult:
    tables: list[TableResult] = field(default_factory=list)
    duration_ms: int = 0

    @property
    def total_rows(self) -> int:
        return sum(t.rows for t in self.tables)


# --------------------------------------------------------------------------- #
# Watermark (stored in BigQuery analytics._sync_state)
# --------------------------------------------------------------------------- #
def _read_watermark(client: bigquery.Client, target: str) -> datetime:
    job = client.query(
        f"SELECT last_synced_at FROM `{table_ref(SYNC_STATE)}` WHERE target_name = @t",
        job_config=bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("t", "STRING", target)]
        ),
    )
    rows = list(job.result())
    if rows and rows[0].last_synced_at:
        ts = rows[0].last_synced_at
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    return _EPOCH


def _write_watermark(
    client: bigquery.Client, target: str, ts: datetime, rows: int
) -> None:
    client.query(
        f"""
        MERGE `{table_ref(SYNC_STATE)}` T
        USING (
          SELECT @t AS target_name, @ts AS last_synced_at,
                 @rows AS rows_synced, CURRENT_TIMESTAMP() AS last_run_at
        ) S
        ON T.target_name = S.target_name
        WHEN MATCHED THEN UPDATE SET
          last_synced_at = S.last_synced_at,
          rows_synced = S.rows_synced,
          last_run_at = S.last_run_at
        WHEN NOT MATCHED THEN INSERT ROW
        """,
        job_config=bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("t", "STRING", target),
                bigquery.ScalarQueryParameter("ts", "TIMESTAMP", ts),
                bigquery.ScalarQueryParameter("rows", "INT64", int(rows)),
            ]
        ),
    ).result()


# --------------------------------------------------------------------------- #
# Stage + MERGE
# --------------------------------------------------------------------------- #
def _stage_and_merge(
    client: bigquery.Client, target: str, df: pd.DataFrame, keys: list[str]
) -> None:
    if df.empty:
        return
    schema = TABLES[target]
    df = df.reindex(columns=[f.name for f in schema])
    stage = table_ref(f"_stage_{target}")

    client.load_table_from_dataframe(
        df,
        stage,
        job_config=bigquery.LoadJobConfig(
            schema=schema,
            write_disposition=bigquery.WriteDisposition.WRITE_TRUNCATE,
        ),
    ).result()

    cols = [f.name for f in schema]
    on = " AND ".join(f"T.{k} = S.{k}" for k in keys)
    set_clause = ", ".join(f"{c} = S.{c}" for c in cols if c not in keys)
    insert_cols = ", ".join(cols)
    insert_vals = ", ".join(f"S.{c}" for c in cols)

    client.query(
        f"""
        MERGE `{table_ref(target)}` T
        USING `{stage}` S ON {on}
        WHEN MATCHED THEN UPDATE SET {set_clause}
        WHEN NOT MATCHED THEN INSERT ({insert_cols}) VALUES ({insert_vals})
        """
    ).result()
    client.delete_table(stage, not_found_ok=True)


# --------------------------------------------------------------------------- #
# Per-target reads
# --------------------------------------------------------------------------- #
def _sync_dim_mitre(pg, client: bigquery.Client) -> int:
    df = pd.read_sql_query(
        text("SELECT technique_id, technique_name, tactic, description "
             "FROM mitre_techniques"),
        pg,
    )
    _stage_and_merge(client, "dim_mitre_techniques", df, MERGE_KEYS["dim_mitre_techniques"])
    return len(df)


def _sync_dim_rules(pg, client: bigquery.Client) -> int:
    df = pd.read_sql_query(
        text("SELECT rule_id, rule_name, rule_type, severity FROM detection_rules"),
        pg,
    )
    df["rule_id"] = df["rule_id"].astype("Int64")
    _stage_and_merge(client, "dim_detection_rules", df, MERGE_KEYS["dim_detection_rules"])
    return len(df)


_FACT_ALERTS_SQL = """
SELECT
    a.alert_id,
    a.triggered_at,
    a.severity,
    a.status                         AS alert_status,
    a.rule_id,
    r.rule_name,
    r.rule_type,
    m.technique_id                   AS mitre_technique_id,
    m.technique_name,
    m.tactic,
    host(a.source_ip)                AS source_ip,
    a.username,
    i.incident_id,
    i.status                         AS incident_status,
    i.opened_at,
    i.closed_at,
    ROUND(EXTRACT(EPOCH FROM (i.closed_at - i.opened_at)) / 3600.0, 2)
                                     AS resolution_hours,
    GREATEST(a.created_at, a.updated_at, COALESCE(i.updated_at, a.created_at))
                                     AS row_modified_at
FROM alerts a
JOIN detection_rules  r ON r.rule_id = a.rule_id
JOIN mitre_techniques m ON m.technique_id = r.mitre_technique_id
LEFT JOIN incidents   i ON i.alert_id = a.alert_id
WHERE GREATEST(a.created_at, a.updated_at, COALESCE(i.updated_at, a.created_at)) > :wm
ORDER BY row_modified_at
"""


def _sync_fact_alerts(pg, client: bigquery.Client, wm: datetime) -> tuple[int, datetime]:
    df = pd.read_sql_query(text(_FACT_ALERTS_SQL), pg, params={"wm": wm})
    if df.empty:
        return 0, wm
    for col in ("alert_id", "rule_id", "incident_id"):
        df[col] = df[col].astype("Int64")
    df["synced_at"] = datetime.now(timezone.utc)
    _stage_and_merge(client, "fact_alerts", df, MERGE_KEYS["fact_alerts"])
    return len(df), df["row_modified_at"].max().to_pydatetime()


def _sync_fact_logs_daily(pg, client: bigquery.Client, wm: datetime) -> tuple[int, datetime]:
    changed = pd.read_sql_query(
        text('SELECT DISTINCT date_trunc(\'day\', "timestamp")::date AS d '
             "FROM logs_raw WHERE ingested_at > :wm"),
        pg,
        params={"wm": wm},
    )
    if changed.empty:
        return 0, wm
    dates = list(changed["d"])

    df = pd.read_sql_query(
        text('SELECT date_trunc(\'day\', "timestamp")::date AS log_date, '
             "source_system, event_type, status, count(*) AS event_count "
             "FROM logs_raw "
             'WHERE date_trunc(\'day\', "timestamp")::date = ANY(:dates) '
             "GROUP BY 1, 2, 3, 4"),
        pg,
        params={"dates": dates},
    )
    df["event_count"] = df["event_count"].astype("Int64")
    df["synced_at"] = datetime.now(timezone.utc)
    _stage_and_merge(client, "fact_logs_daily", df, MERGE_KEYS["fact_logs_daily"])

    new_wm = pd.read_sql_query(
        text("SELECT max(ingested_at) AS m FROM logs_raw"), pg
    )["m"].iloc[0]
    new_wm = pd.Timestamp(new_wm).to_pydatetime()
    if new_wm.tzinfo is None:
        new_wm = new_wm.replace(tzinfo=timezone.utc)
    return len(df), new_wm


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def sync(*, full: bool = False) -> SyncResult:
    started = time.monotonic()
    client = bigquery_client()
    result = SyncResult()
    now = datetime.now(timezone.utc)

    with get_engine("ro").connect() as pg:
        n = _sync_dim_mitre(pg, client)
        _write_watermark(client, "dim_mitre_techniques", now, n)
        result.tables.append(TableResult("dim_mitre_techniques", n, now))

        n = _sync_dim_rules(pg, client)
        _write_watermark(client, "dim_detection_rules", now, n)
        result.tables.append(TableResult("dim_detection_rules", n, now))

        wm = _EPOCH if full else _read_watermark(client, "fact_alerts")
        n, new_wm = _sync_fact_alerts(pg, client, wm)
        _write_watermark(client, "fact_alerts", new_wm, n)
        result.tables.append(TableResult("fact_alerts", n, new_wm))

        wm = _EPOCH if full else _read_watermark(client, "fact_logs_daily")
        n, new_wm = _sync_fact_logs_daily(pg, client, wm)
        _write_watermark(client, "fact_logs_daily", new_wm, n)
        result.tables.append(TableResult("fact_logs_daily", n, new_wm))

    result.duration_ms = int((time.monotonic() - started) * 1000)
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Sync PostgreSQL -> BigQuery.")
    p.add_argument("--full", action="store_true",
                   help="ignore the watermark and re-sync every row")
    args = p.parse_args(argv)

    res = sync(full=args.full)
    print(f"sync complete in {res.duration_ms} ms, {res.total_rows} row(s) merged")
    for t in res.tables:
        print(f"  {t.target:<22} {t.rows:>6} rows   watermark -> {t.watermark_after:%Y-%m-%d %H:%M:%S}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
