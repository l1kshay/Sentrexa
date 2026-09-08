"""SQLAlchemy ORM models - the shared operational data layer.

Mirrors ``sql/schema/001_core_schema.sql`` and ``002_rejected_records.sql``
exactly (same table and column names). The SQL files remain the source of truth
for DDL (indexes, partial indexes, check constraints); these classes are how the
ingestion / detection / alerting modules read and write rows with parameterized,
ORM-mediated queries - never string-built SQL.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Integer,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, TIMESTAMP
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

_TS = TIMESTAMP(timezone=True)


class Base(DeclarativeBase):
    pass


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    technique_id: Mapped[str] = mapped_column(Text, primary_key=True)
    technique_name: Mapped[str] = mapped_column(Text, nullable=False)
    tactic: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")

    rules: Mapped[list["DetectionRule"]] = relationship(back_populates="technique")


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    __table_args__ = (
        CheckConstraint(
            "rule_type IN ('brute_force', 'off_hours_login', 'privilege_escalation')",
            name="ck_detection_rules_type",
        ),
        CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="ck_detection_rules_severity",
        ),
    )

    rule_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    rule_type: Mapped[str] = mapped_column(Text, nullable=False)
    threshold_value: Mapped[int | None] = mapped_column(Integer)
    time_window_minutes: Mapped[int | None] = mapped_column(Integer)
    mitre_technique_id: Mapped[str] = mapped_column(
        Text, ForeignKey("mitre_techniques.technique_id"), nullable=False
    )
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    params: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(_TS, nullable=False, server_default=text("now()"))

    technique: Mapped["MitreTechnique"] = relationship(back_populates="rules")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="rule")


class LogRaw(Base):
    __tablename__ = "logs_raw"

    log_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column("timestamp", _TS, nullable=False)
    source_system: Mapped[str] = mapped_column(Text, nullable=False)
    source_ip: Mapped[str | None] = mapped_column(INET)
    username: Mapped[str | None] = mapped_column(Text)
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    raw_message: Mapped[str] = mapped_column(Text, nullable=False)
    processed: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    ingested_at: Mapped[datetime] = mapped_column(_TS, nullable=False, server_default=text("now()"))
    ingest_batch: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    dedup_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)

    links: Mapped[list["AlertLogLink"]] = relationship(back_populates="log")


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')", name="ck_alerts_severity"
        ),
        CheckConstraint(
            "status IN ('New', 'Acknowledged', 'Dismissed')", name="ck_alerts_status"
        ),
        UniqueConstraint("dedup_key", name="uq_alerts_dedup_key"),
    )

    alert_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    rule_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("detection_rules.rule_id"), nullable=False
    )
    triggered_at: Mapped[datetime] = mapped_column(_TS, nullable=False)
    source_ip: Mapped[str | None] = mapped_column(INET)
    username: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="New")
    created_at: Mapped[datetime] = mapped_column(_TS, nullable=False, server_default=text("now()"))
    updated_at: Mapped[datetime] = mapped_column(_TS, nullable=False, server_default=text("now()"))
    dedup_key: Mapped[str] = mapped_column(Text, nullable=False)

    rule: Mapped["DetectionRule"] = relationship(back_populates="alerts")
    links: Mapped[list["AlertLogLink"]] = relationship(
        back_populates="alert", cascade="all, delete-orphan"
    )
    incident: Mapped["Incident | None"] = relationship(
        back_populates="alert", uselist=False
    )


class AlertLogLink(Base):
    __tablename__ = "alert_log_links"

    alert_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("alerts.alert_id", ondelete="CASCADE"), primary_key=True
    )
    log_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("logs_raw.log_id"), primary_key=True
    )

    alert: Mapped["Alert"] = relationship(back_populates="links")
    log: Mapped["LogRaw"] = relationship(back_populates="links")


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(
            "status IN ('Open', 'In Review', 'Closed')", name="ck_incidents_status"
        ),
    )

    incident_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    alert_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("alerts.alert_id"), nullable=False, unique=True
    )
    opened_at: Mapped[datetime] = mapped_column(_TS, nullable=False, server_default=text("now()"))
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="Open")
    assigned_to: Mapped[str | None] = mapped_column(Text)
    resolution_notes: Mapped[str | None] = mapped_column(Text)
    closed_at: Mapped[datetime | None] = mapped_column(_TS)
    updated_at: Mapped[datetime] = mapped_column(_TS, nullable=False, server_default=text("now()"))

    alert: Mapped["Alert"] = relationship(back_populates="incident")


class DetectionRunLog(Base):
    __tablename__ = "detection_run_log"
    __table_args__ = (
        CheckConstraint(
            "status IN ('success', 'partial', 'error')", name="ck_run_log_status"
        ),
    )

    run_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    run_timestamp: Mapped[datetime] = mapped_column(
        _TS, nullable=False, server_default=text("now()")
    )
    stage: Mapped[str] = mapped_column(Text, nullable=False, server_default="detect")
    logs_processed: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    alerts_generated: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    status: Mapped[str] = mapped_column(Text, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[int | None] = mapped_column(Integer)


class RejectedRecord(Base):
    __tablename__ = "rejected_records"

    reject_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    rejected_at: Mapped[datetime] = mapped_column(_TS, nullable=False, server_default=text("now()"))
    stage: Mapped[str] = mapped_column(Text, nullable=False, server_default="ingestion")
    source_file: Mapped[str | None] = mapped_column(Text)
    line_number: Mapped[int | None] = mapped_column(Integer)
    raw_line: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    dedup_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
