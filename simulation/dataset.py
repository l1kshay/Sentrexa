"""Dataset runner - the "Log Simulator" entrypoint.

Builds a full simulated feed (benign background traffic + every seeded attack
scenario), writes it to ``data/raw/<end-timestamp>.ndjson`` as a raw one-line-
per-event feed, and writes a sidecar ``<...>.scenarios.json`` manifest recording
exactly which lines belong to which seeded attack (ground truth for Phase 3).

Usage:
    python -m simulation.dataset
    python -m simulation.dataset --seed 42 --benign 8000 --window-hours 72
    python -m simulation.dataset --inject-malformed 5      # for Phase 2 quarantine tests
    python -m simulation.dataset --end 2026-09-07T12:00:00Z --out /tmp/run
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from config.settings import settings

from .attack_scenarios import SeededScenario, build_all_scenarios
from .common import make_faker, make_rng, window
from .generators.auth_log_generator import generate_auth_events
from .generators.firewall_log_generator import generate_firewall_events
from .generators.web_log_generator import generate_web_events
from .schema import LogEvent

# how the benign budget is split across sources
_SOURCE_MIX = {"auth": 0.45, "web": 0.35, "firewall": 0.20}

# Malformed line templates for Phase 2 quarantine testing. All are structurally
# invalid at the feed level (not JSON, or missing/empty required keys, or an
# unknown source hint) so ingestion must quarantine them at load time. Phase 2
# adds its own tests for lines that are structurally fine but whose raw_message
# matches no known log grammar.
_MALFORMED_TEMPLATES = [
    'this is not json at all -- {n}',
    '{{"source_system": "auth"}}',                     # missing raw_message
    '{{"source_system": "web", "raw_message": ""}}',   # empty raw_message
    '{{"source_system": "weather", "raw_message": "temp=22C humidity=60"}}',  # unknown source
    '{{"raw_message": "Sep  7 orphan line with no source hint"}}',            # missing source
    '{{"source_system": "auth", "raw_message": "Sep  7 truncated line no close',  # invalid JSON
]


@dataclass
class BuiltDataset:
    end: datetime
    start: datetime
    seed: int
    benign_count: int
    lines: list[str]                 # every line to be written, in order
    scenarios: list[SeededScenario]  # with event_line_indexes populated
    malformed_line_indexes: list[int]

    @property
    def total_lines(self) -> int:
        return len(self.lines)


def build_dataset(
    *,
    seed: int,
    benign_events: int,
    window_hours: int,
    end: datetime | None = None,
    inject_malformed: int = 0,
) -> BuiltDataset:
    end = (end or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start, end = window(end, window_hours)

    rng = make_rng(seed)
    make_faker(seed)  # seed Faker's global instance for any incidental use

    n_auth = int(benign_events * _SOURCE_MIX["auth"])
    n_web = int(benign_events * _SOURCE_MIX["web"])
    n_fw = benign_events - n_auth - n_web

    benign: list[LogEvent] = []
    benign += generate_auth_events(
        rng, count=n_auth, start=start, end=end,
        users=settings.simulation.internal_users,
        admin_users=settings.simulation.admin_users,
    )
    benign += generate_web_events(
        rng, count=n_web, start=start, end=end,
        users=settings.simulation.internal_users,
    )
    benign += generate_firewall_events(rng, count=n_fw, start=start, end=end)

    scenarios = build_all_scenarios(rng, start, end, settings.simulation)
    scenario_event_ids: dict[int, str] = {
        id(ev): sc.scenario_id for sc in scenarios for ev in sc.events
    }

    all_events: list[LogEvent] = benign + [ev for sc in scenarios for ev in sc.events]
    all_events.sort(key=lambda e: e.timestamp)

    # splice in malformed lines at random positions
    items: list[object] = list(all_events)
    malformed_lines = _make_malformed(rng, inject_malformed)
    for line in malformed_lines:
        items.insert(rng.randint(0, len(items)), _Malformed(line))

    # render + record line indexes
    lines: list[str] = []
    per_scenario: dict[str, list[int]] = {sc.scenario_id: [] for sc in scenarios}
    malformed_idx: list[int] = []
    for idx, item in enumerate(items):
        if isinstance(item, _Malformed):
            lines.append(item.text)
            malformed_idx.append(idx)
            continue
        lines.append(item.to_ndjson_line())
        sid = scenario_event_ids.get(id(item))
        if sid is not None:
            per_scenario[sid].append(idx)

    for sc in scenarios:
        sc.event_line_indexes = per_scenario[sc.scenario_id]

    return BuiltDataset(
        end=end, start=start, seed=seed, benign_count=len(benign),
        lines=lines, scenarios=scenarios, malformed_line_indexes=malformed_idx,
    )


class _Malformed:
    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text


def _make_malformed(rng: random.Random, n: int) -> list[str]:
    out: list[str] = []
    for i in range(n):
        template = _MALFORMED_TEMPLATES[i % len(_MALFORMED_TEMPLATES)]
        out.append(template.format(n=i))
    return out


def _manifest(ds: BuiltDataset, output_file: str) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "seed": ds.seed,
        "window": {
            "start": ds.start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end": ds.end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "output_file": output_file,
        "total_events": ds.total_lines,
        "benign_events": ds.benign_count,
        "malformed_line_indexes": ds.malformed_line_indexes,
        "scenarios": [sc.oracle() for sc in ds.scenarios],
    }


def write_dataset(ds: BuiltDataset, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = ds.end.strftime("%Y%m%dT%H%M%SZ")
    feed_path = out_dir / f"{stamp}.ndjson"
    manifest_path = out_dir / f"{stamp}.scenarios.json"

    feed_path.write_text("\n".join(ds.lines) + "\n", encoding="utf-8")
    manifest_path.write_text(
        json.dumps(_manifest(ds, feed_path.name), indent=2), encoding="utf-8"
    )
    # pointer to the newest run, so Phase 2 doesn't need to guess the filename
    (out_dir / "_latest.json").write_text(
        json.dumps({"feed": feed_path.name, "manifest": manifest_path.name}, indent=2),
        encoding="utf-8",
    )
    return feed_path, manifest_path


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    sim = settings.simulation
    p = argparse.ArgumentParser(description="Generate a simulated Sentrexa log feed.")
    p.add_argument("--seed", type=int, default=sim.seed)
    p.add_argument("--benign", type=int, default=sim.benign_events,
                   help="approx number of benign background events")
    p.add_argument("--window-hours", type=int, default=sim.window_hours)
    p.add_argument("--out", type=Path, default=sim.output_dir)
    p.add_argument("--inject-malformed", type=int, default=sim.malformed_count,
                   help="number of deliberately corrupt lines to add (Phase 2 tests)")
    p.add_argument("--end", type=_iso, default=None,
                   help="UTC window end (ISO 8601); default = now")
    p.add_argument("--quiet", action="store_true")
    return p.parse_args(argv)


def _iso(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    ds = build_dataset(
        seed=args.seed,
        benign_events=args.benign,
        window_hours=args.window_hours,
        end=args.end,
        inject_malformed=args.inject_malformed,
    )
    feed_path, manifest_path = write_dataset(ds, args.out)

    if not args.quiet:
        print(f"feed     : {feed_path}  ({ds.total_lines} lines)")
        print(f"manifest : {manifest_path}")
        print(f"window   : {ds.start:%Y-%m-%d %H:%M} -> {ds.end:%Y-%m-%d %H:%M} UTC")
        print(f"benign   : {ds.benign_count}   malformed: {len(ds.malformed_line_indexes)}")
        for sc in ds.scenarios:
            print(
                f"  - {sc.scenario_id:<22} rule={sc.expected_rule_type:<20} "
                f"lines={len(sc.event_line_indexes)} "
                f"(>= {sc.expected_min_matches} should match)"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
