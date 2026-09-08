-- Phase 7: change-tracking for the BigQuery incremental sync.
-- Adds a maintained `updated_at` to the two tables whose rows change after
-- creation (alerts: status workflow; incidents: status workflow + closed_at).
-- The BigQuery sync uses GREATEST(alert.updated_at, incident.updated_at) to
-- decide which fact_alerts rows to re-MERGE. Idempotent.

ALTER TABLE alerts    ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_alerts_updated_at ON alerts;
CREATE TRIGGER trg_alerts_updated_at
    BEFORE UPDATE ON alerts
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_incidents_updated_at ON incidents;
CREATE TRIGGER trg_incidents_updated_at
    BEFORE UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX IF NOT EXISTS ix_alerts_updated_at    ON alerts (updated_at);
CREATE INDEX IF NOT EXISTS ix_incidents_updated_at ON incidents (updated_at);
