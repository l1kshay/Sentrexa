"""Engine / session factories, one per privilege level.

    role="admin"  -> DATABASE_URL      (owner; bootstrap/DDL only)
    role="rw"     -> DATABASE_URL_RW   (ingestion, detection, alerting)
    role="ro"     -> DATABASE_URL_RO   (dashboard, reports)

Nothing in the app should call ``create_engine`` directly - go through here so
the privilege boundary is enforced in one place.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Literal

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from config.settings import settings

Role = Literal["admin", "rw", "ro"]

_engines: dict[str, Engine] = {}
_factories: dict[str, sessionmaker[Session]] = {}


def get_engine(role: Role = "rw") -> Engine:
    if role not in _engines:
        url = settings.database.require("admin" if role == "admin" else role)
        _engines[role] = create_engine(url, pool_pre_ping=True, future=True)
    return _engines[role]


def get_sessionmaker(role: Role = "rw") -> sessionmaker[Session]:
    if role not in _factories:
        _factories[role] = sessionmaker(
            bind=get_engine(role), future=True, expire_on_commit=False
        )
    return _factories[role]


@contextmanager
def session_scope(role: Role = "rw") -> Iterator[Session]:
    """Transactional session: commit on success, roll back on error."""
    session = get_sessionmaker(role)()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
