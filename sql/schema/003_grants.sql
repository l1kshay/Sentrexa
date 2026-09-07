-- Least-privilege application roles and their grants.
-- Roles are created here WITHOUT a password (NOLOGIN); `python -m sql.bootstrap`
-- sets a generated password and enables LOGIN afterwards, so no credential ever
-- lives in a committed file.
--
--   sentrexa_ro  - SELECT only. Used by the Streamlit dashboard and reports.
--   sentrexa_rw  - SELECT / INSERT / UPDATE. Used by ingestion, detection, alerting.
--                  No DELETE: the pipeline never removes rows.
-- Idempotent.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sentrexa_ro') THEN
        CREATE ROLE sentrexa_ro NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sentrexa_rw') THEN
        CREATE ROLE sentrexa_rw NOLOGIN;
    END IF;
END$$;

-- Connect + schema visibility
GRANT CONNECT ON DATABASE sentrexa TO sentrexa_ro, sentrexa_rw;
GRANT USAGE  ON SCHEMA public       TO sentrexa_ro, sentrexa_rw;

-- Read-only role
GRANT SELECT ON ALL TABLES IN SCHEMA public TO sentrexa_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO sentrexa_ro;

-- Read/write role (no DELETE, no DDL)
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO sentrexa_rw;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO sentrexa_rw;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE ON TABLES TO sentrexa_rw;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE ON SEQUENCES TO sentrexa_rw;

-- Explicitly ensure the read-only role can never write, even if a future
-- default-privilege change is fat-fingered.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public FROM sentrexa_ro;
