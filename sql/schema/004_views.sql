-- Read-only convenience views for the dashboard, reports, and (Phase 7) the
-- BigQuery sync. Idempotent.

-- One denormalized row per alert: rule + MITRE technique + incident outcome.
CREATE OR REPLACE VIEW v_alert_enriched AS
SELECT
    a.alert_id,
    a.triggered_at,
    a.severity,
    a.status                     AS alert_status,
    a.source_ip,
    a.username,
    r.rule_id,
    r.rule_name,
    r.rule_type,
    m.technique_id               AS mitre_technique_id,
    m.technique_name,
    m.tactic,
    i.incident_id,
    i.status                     AS incident_status,
    i.opened_at,
    i.closed_at,
    i.assigned_to,
    i.resolution_notes,
    ROUND(EXTRACT(EPOCH FROM (i.closed_at - i.opened_at)) / 3600.0, 2)
                                 AS resolution_hours
FROM alerts a
JOIN detection_rules  r ON r.rule_id = a.rule_id
JOIN mitre_techniques m ON m.technique_id = r.mitre_technique_id
LEFT JOIN incidents   i ON i.alert_id = a.alert_id;

-- Daily log volume by source / event_type / status (feeds fact_logs_daily later).
CREATE OR REPLACE VIEW v_logs_daily AS
SELECT
    date_trunc('day', "timestamp")::date AS log_date,
    source_system,
    event_type,
    status,
    count(*)                             AS event_count
FROM logs_raw
GROUP BY 1, 2, 3, 4;

GRANT SELECT ON v_alert_enriched, v_logs_daily TO sentrexa_ro, sentrexa_rw;
