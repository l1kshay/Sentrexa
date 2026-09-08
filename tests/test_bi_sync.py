"""Phase 7 tests: PostgreSQL -> BigQuery sync.

These hit the real BigQuery dataset and the real database, so they need
Application Default Credentials (`gcloud auth application-default login`) and a
reachable DB - they skip cleanly otherwise. They are excluded from the CI
"not db" run.

Covers the spec's required check: re-running the sync on the same data does not
create duplicate rows in fact_alerts. Also verifies the incremental path picks
up an incident status change.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

pytestmark = pytest.mark.db


@pytest.fixture(scope="module")
def bq():
    bqmod = pytest.importorskip("google.cloud.bigquery")  # noqa: F841
    from bi_export.client import bigquery_client, table_ref

    try:
        client = bigquery_client()
        client.query("SELECT 1").result()
    except Exception as exc:  # pragma: no cover - depends on local auth
        pytest.skip(f"BigQuery not reachable (need ADC): {exc}")

    from bi_export.schema.bigquery_schema import create_schema

    create_schema()
    return client, table_ref


def _count(client, ref: str) -> int:
    return list(client.query(f"SELECT count(*) AS n FROM `{ref}`").result())[0].n


def _dupes(client, ref: str, keys: str) -> int:
    sql = f"SELECT 1 FROM `{ref}` GROUP BY {keys} HAVING count(*) > 1"
    return len(list(client.query(sql).result()))


class TestSyncIdempotency:
    def test_rerun_does_not_duplicate_fact_rows(self, bq, admin_engine) -> None:
        from bi_export.sync_to_bigquery import sync

        client, table_ref = bq
        fact_alerts = table_ref("fact_alerts")
        fact_daily = table_ref("fact_logs_daily")

        sync(full=True)
        alerts_1 = _count(client, fact_alerts)
        daily_1 = _count(client, fact_daily)

        # DB row count is the ground truth for fact_alerts
        with admin_engine.connect() as conn:
            pg_alerts = conn.execute(text("SELECT count(*) FROM alerts")).scalar_one()
        assert alerts_1 == pg_alerts

        sync()  # incremental re-run on unchanged data
        assert _count(client, fact_alerts) == alerts_1
        assert _count(client, fact_daily) == daily_1
        assert _dupes(client, fact_alerts, "alert_id") == 0
        assert _dupes(
            client, fact_daily, "log_date, source_system, event_type, status"
        ) == 0

    def test_incremental_picks_up_an_incident_change(self, bq, admin_engine) -> None:
        from alerting.incident_manager import set_incident_status
        from bi_export.sync_to_bigquery import sync

        client, table_ref = bq
        fact_alerts = table_ref("fact_alerts")

        with admin_engine.connect() as conn:
            row = conn.execute(
                text("SELECT incident_id, alert_id, status FROM incidents "
                     "WHERE status = 'Open' ORDER BY incident_id LIMIT 1")
            ).first()
        if row is None:
            pytest.skip("no Open incident to exercise the incremental path")

        sync(full=True)
        before = _count(client, fact_alerts)

        session = Session(bind=admin_engine)
        try:
            set_incident_status(session, row.incident_id, "In Review",
                                assigned_to="pytest")
            session.commit()

            res = sync()  # incremental
            merged = next(t.rows for t in res.tables if t.target == "fact_alerts")
            assert merged >= 1  # the changed alert re-synced

            got = list(client.query(
                f"SELECT incident_status FROM `{fact_alerts}` "
                f"WHERE alert_id = {int(row.alert_id)}"
            ).result())[0].incident_status
            assert got == "In Review"
            assert _count(client, fact_alerts) == before  # updated in place, not appended
        finally:
            # restore state
            set_incident_status(session, row.incident_id, "Open")
            session.commit()
            session.close()
            sync()
