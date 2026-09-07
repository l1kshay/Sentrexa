"""Shared pytest fixtures."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, text

from config.settings import settings
from simulation.dataset import BuiltDataset, build_dataset

FIXED_END = datetime(2026, 9, 7, 12, 0, 0, tzinfo=timezone.utc)
FIXED_SEED = 1337


@pytest.fixture(scope="session")
def built_dataset() -> BuiltDataset:
    """A deterministic dataset: fixed seed + fixed window end + malformed lines."""
    return build_dataset(
        seed=FIXED_SEED,
        benign_events=2500,
        window_hours=168,
        end=FIXED_END,
        inject_malformed=6,
    )


@pytest.fixture(scope="session")
def _admin_url() -> str | None:
    return settings.database.admin_url


@pytest.fixture(scope="session")
def admin_engine(_admin_url):
    """An admin-privileged engine for DB integration tests (setup + teardown).

    Skips the whole test if no admin URL is configured or the server is
    unreachable, so `pytest` still runs cleanly with no database.
    """
    if not _admin_url:
        pytest.skip("no DATABASE_URL configured")
    engine = create_engine(_admin_url, future=True, pool_pre_ping=True)
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # pragma: no cover - depends on environment
        engine.dispose()
        pytest.skip(f"database unreachable: {exc}")
    yield engine
    engine.dispose()


@pytest.fixture
def cleanup_batch(admin_engine):
    """Yields a callable to register batch names; deletes their rows on teardown."""
    batches: list[str] = []

    def _register(name: str) -> str:
        batches.append(name)
        return name

    yield _register

    with admin_engine.begin() as conn:
        for name in batches:
            conn.execute(
                text("DELETE FROM logs_raw WHERE ingest_batch = :b"), {"b": name}
            )
            conn.execute(
                text("DELETE FROM rejected_records WHERE source_file = :b"), {"b": name}
            )
        conn.execute(
            text(
                "DELETE FROM detection_run_log "
                "WHERE stage = 'ingest' AND run_timestamp > now() - interval '1 hour'"
            )
        )


@pytest.fixture(scope="session")
def feed_records(built_dataset: BuiltDataset) -> list[dict | None]:
    """Each feed line parsed as JSON, or None if it is not valid JSON."""
    out: list[dict | None] = []
    for line in built_dataset.lines:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            out.append(None)
    return out
