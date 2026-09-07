"""One-time database bootstrap.

Uses the admin connection (``DATABASE_URL``) to:
  1. apply the schema DDL in ``sql/schema/`` (idempotent),
  2. create the least-privilege roles ``sentrexa_ro`` / ``sentrexa_rw`` and grants,
  3. set a generated password for each role and enable LOGIN,
  4. rewrite the ``DATABASE_URL_RW`` / ``DATABASE_URL_RO`` lines in ``.env``.

Run:
    python -m sql.bootstrap                 # first-time setup (only sets passwords
                                            # if .env still has CHANGE_ME)
    python -m sql.bootstrap --reset-passwords
    python -m sql.bootstrap --schema-only

Passwords are generated with secrets.token_urlsafe and never printed in full or
committed anywhere - they go straight into the gitignored .env.
"""

from __future__ import annotations

import argparse
import re
import secrets
import sys
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from config.settings import PROJECT_ROOT, settings

SCHEMA_DIR = PROJECT_ROOT / "sql" / "schema"
ENV_PATH = PROJECT_ROOT / ".env"
SCHEMA_FILES = ["001_core_schema.sql", "002_rejected_records.sql", "003_grants.sql"]
_SAFE_PW = re.compile(r"^[A-Za-z0-9_-]+$")


def _gen_password() -> str:
    pw = secrets.token_urlsafe(24)
    assert _SAFE_PW.match(pw), "generated password contains an unsafe character"
    return pw


def _role_url(admin_url: str, username: str, password: str) -> str:
    return make_url(admin_url).set(username=username, password=password).render_as_string(
        hide_password=False
    )


def _apply_schema(admin_url: str) -> None:
    engine = create_engine(admin_url, future=True)
    with engine.begin() as conn:
        for name in SCHEMA_FILES:
            sql = (SCHEMA_DIR / name).read_text(encoding="utf-8")
            print(f"  applying {name} ...")
            conn.exec_driver_sql(sql)
    engine.dispose()


def _current_env_text() -> str:
    if not ENV_PATH.exists():
        sys.exit(f"ERROR: {ENV_PATH} not found. Copy .env.example to .env first.")
    return ENV_PATH.read_text(encoding="utf-8")


def _env_needs_passwords(env_text: str) -> bool:
    return bool(re.search(r"^DATABASE_URL_R[WO]=.*CHANGE_ME", env_text, re.MULTILINE))


def _rewrite_env(env_text: str, rw_url: str, ro_url: str) -> str:
    env_text = re.sub(r"^DATABASE_URL_RW=.*$", f"DATABASE_URL_RW={rw_url}",
                      env_text, flags=re.MULTILINE)
    env_text = re.sub(r"^DATABASE_URL_RO=.*$", f"DATABASE_URL_RO={ro_url}",
                      env_text, flags=re.MULTILINE)
    return env_text


def _set_role_password(admin_url: str, role: str, password: str) -> None:
    # role name is a fixed literal; password is validated against _SAFE_PW.
    engine = create_engine(admin_url, future=True)
    with engine.begin() as conn:
        conn.exec_driver_sql(f"ALTER ROLE {role} WITH LOGIN PASSWORD '{password}'")
    engine.dispose()


def _verify(rw_url: str, ro_url: str) -> None:
    print("\nVerifying role privileges ...")
    rw = create_engine(rw_url, future=True)
    with rw.connect() as conn:
        n = conn.execute(text("SELECT count(*) FROM logs_raw")).scalar_one()
        print(f"  sentrexa_rw can SELECT logs_raw (rows={n})")
    rw.dispose()

    ro = create_engine(ro_url, future=True)
    with ro.connect() as conn:
        conn.execute(text("SELECT 1"))
        print("  sentrexa_ro can connect + SELECT")
        try:
            conn.execute(text(
                "INSERT INTO detection_run_log (status) VALUES ('success')"
            ))
            print("  !! sentrexa_ro was able to INSERT - grants are wrong")
            sys.exit(1)
        except Exception:
            print("  sentrexa_ro correctly blocked from INSERT")
    ro.dispose()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Bootstrap the Sentrexa database.")
    p.add_argument("--schema-only", action="store_true",
                   help="apply DDL + grants, do not touch role passwords or .env")
    p.add_argument("--reset-passwords", action="store_true",
                   help="generate new role passwords even if .env already has them")
    args = p.parse_args(argv)

    admin_url = settings.database.require("admin")
    print(f"Admin connection: {make_url(admin_url).render_as_string(hide_password=True)}")

    print("\nApplying schema + grants:")
    _apply_schema(admin_url)

    if args.schema_only:
        print("\n--schema-only: done. Roles exist (NOLOGIN) but no passwords set.")
        return 0

    env_text = _current_env_text()
    if not (args.reset_passwords or _env_needs_passwords(env_text)):
        print("\n.env already has role credentials; leaving them untouched "
              "(use --reset-passwords to rotate).")
        rw_url = settings.database.require("rw")
        ro_url = settings.database.require("ro")
        _verify(rw_url, ro_url)
        return 0

    print("\nGenerating role passwords ...")
    rw_pw, ro_pw = _gen_password(), _gen_password()
    rw_url = _role_url(admin_url, "sentrexa_rw", rw_pw)
    ro_url = _role_url(admin_url, "sentrexa_ro", ro_pw)

    _set_role_password(admin_url, "sentrexa_rw", rw_pw)
    _set_role_password(admin_url, "sentrexa_ro", ro_pw)

    ENV_PATH.write_text(_rewrite_env(env_text, rw_url, ro_url), encoding="utf-8")
    print(f"  wrote DATABASE_URL_RW / DATABASE_URL_RO to {ENV_PATH}")

    # settings is cached; re-read from the freshly written file for verification.
    get_settings_cache_clear()
    _verify(rw_url, ro_url)
    print("\nBootstrap complete.")
    return 0


def get_settings_cache_clear() -> None:
    from config.settings import get_settings

    get_settings.cache_clear()


if __name__ == "__main__":
    raise SystemExit(main())
