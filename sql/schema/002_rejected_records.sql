-- Quarantine table for malformed / unparseable log lines.
-- Ingestion writes here instead of dropping a bad line or crashing the pipeline.
-- Idempotent.

CREATE TABLE IF NOT EXISTS rejected_records (
    reject_id   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rejected_at timestamptz NOT NULL DEFAULT now(),
    stage       text NOT NULL DEFAULT 'ingestion',   -- ingestion | parse
    source_file text,                                -- feed filename
    line_number integer,                             -- 0-based line in that file
    raw_line    text NOT NULL,                       -- the offending line, verbatim
    reason      text NOT NULL,                       -- why it was rejected
    dedup_hash  text NOT NULL                        -- sha256(source_file|line_number|raw_line)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_rejected_dedup_hash ON rejected_records (dedup_hash);
CREATE INDEX IF NOT EXISTS ix_rejected_at ON rejected_records (rejected_at);
