-- Sentrexa operational schema (spec section 5a).
-- Idempotent: safe to run repeatedly. Applied by `python -m sql.bootstrap`.
-- All DDL only; no data. Detection rules and MITRE techniques are seeded in Phase 3.

-- --------------------------------------------------------------------------
-- Reference: MITRE ATT&CK techniques (curated, only what our rules use)
-- --------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mitre_techniques (
    technique_id   text PRIMARY KEY,                 -- e.g. 'T1110.001'
    technique_name text NOT NULL,
    tactic         text NOT NULL,
    description    text NOT NULL DEFAULT ''
);

-- --------------------------------------------------------------------------
-- Detection rules - the engine reads these, never hardcodes them
-- --------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id             integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_name           text NOT NULL UNIQUE,
    rule_type           text NOT NULL
        CHECK (rule_type IN ('brute_force', 'off_hours_login', 'privilege_escalation')),
    threshold_value     integer,                     -- e.g. failed-login count
    time_window_minutes integer,                     -- sliding window for the threshold
    mitre_technique_id  text NOT NULL REFERENCES mitre_techniques (technique_id),
    severity            text NOT NULL
        CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    is_active           boolean NOT NULL DEFAULT true,
    params              jsonb NOT NULL DEFAULT '{}'::jsonb,   -- rule-type-specific extras
    created_at          timestamptz NOT NULL DEFAULT now()
);

-- --------------------------------------------------------------------------
-- Raw normalized logs (source of truth for detection)
-- --------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS logs_raw (
    log_id        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    "timestamp"   timestamptz NOT NULL,             -- event time, parsed from the raw line
    source_system text NOT NULL
        CHECK (source_system IN ('auth', 'web', 'firewall')),
    source_ip     inet,                              -- NULL for IP-less lines (sudo, session close)
    username      text,                              -- NULL for principal-less events (firewall)
    event_type    text NOT NULL,
    status        text NOT NULL,
    raw_message   text NOT NULL,
    processed     boolean NOT NULL DEFAULT false,    -- detection idempotency flag
    ingested_at   timestamptz NOT NULL DEFAULT now(),
    ingest_batch  text NOT NULL DEFAULT '',          -- feed filename this row came from
    dedup_hash    text NOT NULL                      -- sha256(batch|line_no|raw_message)
);

-- Defensive: keep source_ip nullable even if an older deploy created it NOT NULL.
ALTER TABLE logs_raw ALTER COLUMN source_ip DROP NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_logs_raw_dedup_hash ON logs_raw (dedup_hash);
CREATE INDEX IF NOT EXISTS ix_logs_raw_ts_ip     ON logs_raw ("timestamp", source_ip);
CREATE INDEX IF NOT EXISTS ix_logs_raw_type_stat ON logs_raw (event_type, status);
CREATE INDEX IF NOT EXISTS ix_logs_raw_unprocessed
    ON logs_raw (log_id) WHERE processed = false;

-- --------------------------------------------------------------------------
-- Alerts
-- --------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    alert_id     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_id      integer NOT NULL REFERENCES detection_rules (rule_id),
    triggered_at timestamptz NOT NULL,
    source_ip    inet,
    username     text,
    severity     text NOT NULL
        CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status       text NOT NULL DEFAULT 'New'
        CHECK (status IN ('New', 'Acknowledged', 'Dismissed')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    dedup_key    text NOT NULL                       -- rule_id|entity|time-bucket, keeps runs idempotent
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_alerts_dedup_key ON alerts (dedup_key);
CREATE INDEX IF NOT EXISTS ix_alerts_triggered_sev ON alerts (triggered_at, severity);

-- --------------------------------------------------------------------------
-- Alert <-> contributing logs (many-to-many junction)
-- --------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alert_log_links (
    alert_id bigint NOT NULL REFERENCES alerts (alert_id) ON DELETE CASCADE,
    log_id   bigint NOT NULL REFERENCES logs_raw (log_id),
    PRIMARY KEY (alert_id, log_id)
);

CREATE INDEX IF NOT EXISTS ix_alert_log_links_log ON alert_log_links (log_id);

-- --------------------------------------------------------------------------
-- Incidents (one-to-one with alerts, via UNIQUE alert_id)
-- --------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    incident_id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    alert_id         bigint NOT NULL UNIQUE REFERENCES alerts (alert_id),
    opened_at        timestamptz NOT NULL DEFAULT now(),
    status           text NOT NULL DEFAULT 'Open'
        CHECK (status IN ('Open', 'In Review', 'Closed')),
    assigned_to      text,
    resolution_notes text,
    closed_at        timestamptz
);

CREATE INDEX IF NOT EXISTS ix_incidents_status ON incidents (status);

-- --------------------------------------------------------------------------
-- Execution log - one row per pipeline stage per cycle
-- --------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS detection_run_log (
    run_id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_timestamp    timestamptz NOT NULL DEFAULT now(),
    stage            text NOT NULL DEFAULT 'detect',   -- simulate | ingest | detect | alert | sync
    logs_processed   integer NOT NULL DEFAULT 0,
    alerts_generated integer NOT NULL DEFAULT 0,
    status           text NOT NULL
        CHECK (status IN ('success', 'partial', 'error')),
    error_message    text,
    duration_ms      integer
);

CREATE INDEX IF NOT EXISTS ix_run_log_ts ON detection_run_log (run_timestamp);
