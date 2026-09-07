"""Centralized, config-driven settings for Sentrexa.

Every tunable (paths, thresholds, volumes, connection strings) is read from the
environment here and nowhere else. Modules import ``settings`` from this module
rather than reading ``os.environ`` or hardcoding values.

Local development loads values from a gitignored ``.env`` at the project root.
CI provides the same variables via GitHub Actions secrets.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
PROJECT_ROOT: Path = Path(__file__).resolve().parents[1]

# Load .env once, from the project root. Values already in the real environment
# (e.g. CI secrets) win over the file.
load_dotenv(PROJECT_ROOT / ".env", override=False)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _get(name: str, default: str | None = None) -> str | None:
    val = os.environ.get(name, default)
    if val is not None:
        val = val.strip()
    return val or default


def _get_int(name: str, default: int) -> int:
    raw = _get(name)
    try:
        return int(raw) if raw is not None else default
    except ValueError:
        return default


def _get_list(name: str, default: list[str]) -> list[str]:
    raw = _get(name)
    if not raw:
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class DatabaseSettings:
    """PostgreSQL connection strings for each privilege level.

    ``admin_url``  - database owner; used ONLY by one-time bootstrap scripts.
    ``rw_url``     - least-privilege read/write role for ingestion/detection/alerting.
    ``ro_url``     - least-privilege read-only role for the dashboard and reports.
    """

    admin_url: str | None
    rw_url: str | None
    ro_url: str | None

    def require(self, which: str) -> str:
        url = getattr(self, f"{which}_url")
        if not url:
            raise RuntimeError(
                f"Database URL '{which}_url' is not configured. "
                f"Set the matching DATABASE_URL* variable in .env."
            )
        return url


@dataclass(frozen=True)
class SimulationSettings:
    """Knobs for the Phase 1 log simulator."""

    seed: int
    benign_events: int
    window_hours: int
    output_dir: Path
    off_hours_start: int          # local hour the off-hours window opens (inclusive)
    off_hours_end: int            # local hour the off-hours window closes (exclusive)
    brute_force_attempts: int     # failed auths the seeded brute-force burst emits
    brute_force_window_min: int   # minutes the burst is spread across
    malformed_count: int          # deliberately corrupt lines to inject (Phase 2 testing)

    # Pools the generators draw from. Kept small and stable so seeded runs are
    # reproducible and the seeded attacks stand out against the background.
    internal_users: list[str] = field(default_factory=list)
    admin_users: list[str] = field(default_factory=list)
    privilege_escalation_keywords: list[str] = field(default_factory=list)

    def is_off_hours(self, hour: int) -> bool:
        """True if ``hour`` (0-23) falls in the configured off-hours window.

        Handles windows that wrap past midnight (e.g. 20 -> 6).
        """
        start, end = self.off_hours_start, self.off_hours_end
        if start == end:
            return False
        if start < end:
            return start <= hour < end
        return hour >= start or hour < end


@dataclass(frozen=True)
class DashboardAuthSettings:
    cookie_key: str
    cookie_name: str
    cookie_expiry_days: int
    username: str
    display_name: str
    password_hash: str

    def credentials(self) -> dict:
        """The dict shape streamlit-authenticator expects."""
        return {
            "usernames": {
                self.username: {
                    "name": self.display_name,
                    "password": self.password_hash,
                    "email": f"{self.username}@sentrexa.local",
                }
            }
        }

    @property
    def configured(self) -> bool:
        return bool(self.password_hash and self.password_hash != "CHANGE_ME")


@dataclass(frozen=True)
class BigQuerySettings:
    """Phase 7 only. Left unpopulated until then."""

    project_id: str | None
    dataset: str
    location: str
    sa_key_b64: str | None


@dataclass(frozen=True)
class Settings:
    env: str
    database: DatabaseSettings
    simulation: SimulationSettings
    dashboard_auth: DashboardAuthSettings
    bigquery: BigQuerySettings
    project_root: Path = PROJECT_ROOT

    @property
    def is_ci(self) -> bool:
        return self.env == "ci" or os.environ.get("CI") == "true"


# Default identity pools. Deliberately curated (not Faker-random) so that
# detection tests have a stable, known cast of characters.
_DEFAULT_INTERNAL_USERS = [
    "ariwan", "bthomas", "cferrara", "dkhan", "epatel",
    "fokoro", "gnguyen", "hrossi", "imalik", "jsvensson",
]
_DEFAULT_ADMIN_USERS = ["root", "admin", "svc_backup", "helpdesk_admin"]
_DEFAULT_PRIVESC_KEYWORDS = [
    "sudo su",
    "sudo -i",
    "usermod -aG sudo",
    "role change to admin",
    "added to group administrators",
    "GRANT ALL PRIVILEGES",
    "net localgroup administrators",
]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Build the immutable settings object from the environment (cached)."""
    output_dir = Path(_get("SIM_OUTPUT_DIR", "data/raw"))
    if not output_dir.is_absolute():
        output_dir = PROJECT_ROOT / output_dir

    return Settings(
        env=_get("SENTREXA_ENV", "dev"),
        database=DatabaseSettings(
            admin_url=_get("DATABASE_URL"),
            rw_url=_get("DATABASE_URL_RW"),
            ro_url=_get("DATABASE_URL_RO"),
        ),
        simulation=SimulationSettings(
            seed=_get_int("SIM_SEED", 1337),
            benign_events=_get_int("SIM_BENIGN_EVENTS", 6000),
            window_hours=_get_int("SIM_WINDOW_HOURS", 168),
            output_dir=output_dir,
            off_hours_start=_get_int("SIM_OFF_HOURS_START", 20),
            off_hours_end=_get_int("SIM_OFF_HOURS_END", 6),
            brute_force_attempts=_get_int("SIM_BRUTE_FORCE_ATTEMPTS", 12),
            brute_force_window_min=_get_int("SIM_BRUTE_FORCE_WINDOW_MIN", 3),
            malformed_count=_get_int("SIM_MALFORMED_COUNT", 0),
            internal_users=_get_list("SIM_INTERNAL_USERS", _DEFAULT_INTERNAL_USERS),
            admin_users=_get_list("SIM_ADMIN_USERS", _DEFAULT_ADMIN_USERS),
            privilege_escalation_keywords=_get_list(
                "SIM_PRIVESC_KEYWORDS", _DEFAULT_PRIVESC_KEYWORDS
            ),
        ),
        dashboard_auth=DashboardAuthSettings(
            cookie_key=_get("DASHBOARD_AUTH_COOKIE_KEY", "dev_only_change_me"),
            cookie_name=_get("DASHBOARD_AUTH_COOKIE_NAME", "sentrexa_auth"),
            cookie_expiry_days=_get_int("DASHBOARD_AUTH_COOKIE_EXPIRY_DAYS", 7),
            username=_get("DASHBOARD_AUTH_USERNAME", "analyst"),
            display_name=_get("DASHBOARD_AUTH_NAME", "SOC Analyst"),
            password_hash=_get("DASHBOARD_AUTH_PASSWORD_HASH", "CHANGE_ME"),
        ),
        bigquery=BigQuerySettings(
            project_id=_get("GCP_PROJECT_ID"),
            dataset=_get("BIGQUERY_DATASET", "analytics"),
            location=_get("BIGQUERY_LOCATION", "US"),
            sa_key_b64=_get("GCP_SA_KEY_B64"),
        ),
    )


# Convenience module-level handle.
settings: Settings = get_settings()
