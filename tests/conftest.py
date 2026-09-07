"""Shared pytest fixtures."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

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
def feed_records(built_dataset: BuiltDataset) -> list[dict | None]:
    """Each feed line parsed as JSON, or None if it is not valid JSON."""
    out: list[dict | None] = []
    for line in built_dataset.lines:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            out.append(None)
    return out
