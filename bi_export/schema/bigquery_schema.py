"""BigQuery star schema (spec section 5b) and idempotent provisioning.

    analytics.fact_alerts          one denormalized row per alert
    analytics.fact_logs_daily      daily log volume by source / type / status
    analytics.dim_mitre_techniques technique reference
    analytics.dim_detection_rules  rule reference

Run:
    python -m bi_export.schema.bigquery_schema            # create dataset + tables
    python -m bi_export.schema.bigquery_schema --drop     # drop them (careful)
"""

from __future__ import annotations

import argparse

from google.cloud import bigquery

from bi_export.client import bigquery_client, dataset_ref, table_ref
from config.settings import settings

_F = bigquery.SchemaField

# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
FACT_ALERTS = [
    _F("alert_id", "INT64", mode="REQUIRED"),
    _F("triggered_at", "TIMESTAMP", mode="REQUIRED"),
    _F("severity", "STRING"),
    _F("alert_status", "STRING"),
    _F("rule_id", "INT64"),
    _F("rule_name", "STRING"),
    _F("rule_type", "STRING"),
    _F("mitre_technique_id", "STRING"),
    _F("technique_name", "STRING"),
    _F("tactic", "STRING"),
    _F("source_ip", "STRING"),
    _F("username", "STRING"),
    _F("incident_id", "INT64"),
    _F("incident_status", "STRING"),
    _F("opened_at", "TIMESTAMP"),
    _F("closed_at", "TIMESTAMP"),
    _F("resolution_hours", "FLOAT64"),
    _F("row_modified_at", "TIMESTAMP"),   # GREATEST(alert/ incident change times)
    _F("synced_at", "TIMESTAMP"),
]

FACT_LOGS_DAILY = [
    _F("log_date", "DATE", mode="REQUIRED"),
    _F("source_system", "STRING", mode="REQUIRED"),
    _F("event_type", "STRING", mode="REQUIRED"),
    _F("status", "STRING", mode="REQUIRED"),
    _F("event_count", "INT64"),
    _F("synced_at", "TIMESTAMP"),
]

DIM_MITRE_TECHNIQUES = [
    _F("technique_id", "STRING", mode="REQUIRED"),
    _F("technique_name", "STRING"),
    _F("tactic", "STRING"),
    _F("description", "STRING"),
]

DIM_DETECTION_RULES = [
    _F("rule_id", "INT64", mode="REQUIRED"),
    _F("rule_name", "STRING"),
    _F("rule_type", "STRING"),
    _F("severity", "STRING"),
]

TABLES: dict[str, list[bigquery.SchemaField]] = {
    "fact_alerts": FACT_ALERTS,
    "fact_logs_daily": FACT_LOGS_DAILY,
    "dim_mitre_techniques": DIM_MITRE_TECHNIQUES,
    "dim_detection_rules": DIM_DETECTION_RULES,
}

# Internal bookkeeping table - the incremental-sync watermark. Not part of the
# star schema; the BI tools never read it.
SYNC_STATE = "_sync_state"
SYNC_STATE_SCHEMA = [
    _F("target_name", "STRING", mode="REQUIRED"),
    _F("last_synced_at", "TIMESTAMP"),
    _F("rows_synced", "INT64"),
    _F("last_run_at", "TIMESTAMP"),
]

# natural key(s) used by the sync MERGE
MERGE_KEYS: dict[str, list[str]] = {
    "fact_alerts": ["alert_id"],
    "fact_logs_daily": ["log_date", "source_system", "event_type", "status"],
    "dim_mitre_techniques": ["technique_id"],
    "dim_detection_rules": ["rule_id"],
}


def _table(name: str) -> bigquery.Table:
    t = bigquery.Table(table_ref(name), schema=TABLES[name])
    if name == "fact_alerts":
        t.time_partitioning = bigquery.TimePartitioning(field="triggered_at")
        t.clustering_fields = ["severity", "mitre_technique_id"]
    elif name == "fact_logs_daily":
        t.time_partitioning = bigquery.TimePartitioning(
            type_=bigquery.TimePartitioningType.DAY, field="log_date"
        )
        t.clustering_fields = ["source_system", "event_type"]
    return t


def create_schema() -> list[str]:
    """Create the dataset and all four tables. Idempotent. Returns table ids."""
    client = bigquery_client()

    ds = bigquery.Dataset(dataset_ref())
    ds.location = settings.bigquery.location
    ds.description = "Sentrexa analytics star schema (spec 5b)"
    client.create_dataset(ds, exists_ok=True)

    created: list[str] = []
    for name in TABLES:
        client.create_table(_table(name), exists_ok=True)
        created.append(table_ref(name))

    client.create_table(
        bigquery.Table(table_ref(SYNC_STATE), schema=SYNC_STATE_SCHEMA), exists_ok=True
    )
    created.append(table_ref(SYNC_STATE))
    return created


def drop_schema() -> None:
    client = bigquery_client()
    for name in TABLES:
        client.delete_table(table_ref(name), not_found_ok=True)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Provision the BigQuery star schema.")
    p.add_argument("--drop", action="store_true", help="delete the tables instead")
    args = p.parse_args(argv)

    if args.drop:
        drop_schema()
        print(f"dropped {len(TABLES)} tables from {dataset_ref()}")
        return 0

    for tid in create_schema():
        print(f"ready: {tid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
