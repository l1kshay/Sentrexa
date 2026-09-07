# Sentrexa

**SOC-style log monitoring & alerting dashboard, with a BI & cloud-analytics layer.**

Sentrexa is a simulated Security Operations Center (SOC) monitoring system. It
generates realistic synthetic logs (auth / web / firewall) with deliberately
seeded attack scenarios, normalizes them into PostgreSQL, runs a configurable
**rule-based** (non-ML) detection engine, converts qualifying detections into
severity-tagged alerts mapped to MITRE ATT&CK, auto-escalates high-severity
alerts into incident tickets, and surfaces everything through an auth-gated
Streamlit analyst dashboard plus a weekly HTML report. Phase 7 syncs a
denormalized copy of the alert/incident data into Google BigQuery for three
independent BI dashboards.

## Status

| Phase | Scope | State |
|------:|-------|-------|
| 1 | Log simulation foundation | ✅ done |
| 2 | Ingestion & storage (PostgreSQL) | ✅ done |
| 3 | Detection engine | ✅ done |
| 4 | Alerting, ticketing & MITRE mapping | ✅ done |
| 5 | Dashboard & reporting | ✅ done |
| 6 | Automation, security & deployment | ✅ done |
| 7 | BI & cloud analytics (BigQuery + 3 BI tools) | not started (gated on Phase 6 sign-off) |

## Architecture

```
[Log Simulator] -> [Ingestion & Normalization] -> [PostgreSQL: logs_raw]
      -> [Detection Rule Engine] (reads detection_rules) -> [Alerts + MITRE mapping]
      -> [high-severity alerts auto-escalate] -> [Incidents]
             |                                        |
             v                                        v
     [Streamlit dashboard]                    [BigQuery sync]  (Phase 7)
     [Weekly report]

GitHub Actions -> schedules the simulate -> ingest -> detect cycle
detection_run_log <- one row per stage, every run
rejected_records  <- malformed log lines, quarantined (never dropped)
```

Modules are isolated by concern: `simulation/`, `ingestion/`, `detection/`,
`alerting/`, `dashboard/`, `reports/`, `bi_export/` (Phase 7), with the shared
data layer in `db/` and all tunables in `config/settings.py`.

## Detection rules

Rules live in the **`detection_rules` table**, never in code — the engine
(`detection/rules_engine.py`) loads the active rows and dispatches one pure
detector per `rule_type`. `detection/seed.py` seeds the three rows below
idempotently.

| Rule | Type | Logic | Default threshold | Severity | MITRE |
|------|------|-------|-------------------|----------|-------|
| SSH brute-force burst | `brute_force` | Failed SSH logins grouped by `source_ip`; a sliding time window of `time_window_minutes` containing ≥ `threshold_value` failures fires. Contributing logs = every failure in a qualifying window. One alert per (rule, IP, day). | ≥ 10 failures in 5 min | high | **T1110.001** Brute Force: Password Guessing (Credential Access) |
| Off-hours successful login | `off_hours_login` | A successful `login` whose UTC hour is inside the rule's `[start_hour, end_hour)` window (wraps past midnight). One alert per login event. | 20:00–06:00 UTC | medium | **T1078.003** Valid Accounts: Local Accounts (Defense Evasion) |
| Privilege escalation via sudo keywords | `privilege_escalation` | An `auth` line whose text contains any keyword in the rule's `params.keywords` (case-insensitive) — e.g. `sudo su`, `usermod -aG sudo`, `GRANT ALL PRIVILEGES`. One alert per offending line. | keyword list in `params` | high | **T1548.003** Abuse Elevation Control Mechanism: Sudo and Sudo Caching (Privilege Escalation) |

**MITRE mapping approach.** `mitre/technique_reference.py` is a small curated
table — only the techniques the rules above use — with a single
`RULE_TYPE_TO_TECHNIQUE` map. The seed writes those techniques into
`mitre_techniques`; each `detection_rules` row carries `mitre_technique_id` as a
foreign key. The `v_alert_enriched` view pre-joins alert → rule → technique →
incident so the dashboard, the report, and (Phase 7) BigQuery all read the same
denormalized shape.

**Idempotency.** Ingestion dedupes on `logs_raw.dedup_hash`; detection consumes
only `processed = false` rows and marks them processed in the same transaction;
alerts upsert on `alerts.dedup_key`. Re-running any stage on the same data is a
no-op.

## Local setup

1. **Python 3.14** and a PostgreSQL database (local or hosted, e.g. Neon).
2. `python -m pip install -r requirements.txt`
3. `cp .env.example .env` and set at least `DATABASE_URL` (the database owner).
   `.env` is gitignored — never commit real credentials.
4. **Bootstrap the database** (idempotent — DDL + views, creates the
   least-privilege `sentrexa_ro` / `sentrexa_rw` roles, writes their generated
   credentials back into `.env`, verifies `ro` cannot write):

   ```
   python -m sql.bootstrap
   python -m detection.seed
   ```

5. **Run the pipeline:**

   ```
   python -m simulation.dataset                 # data/raw/<end>.ndjson + .scenarios.json + _latest.json
   python -m simulation.dataset --inject-malformed 6   # add corrupt lines to exercise quarantine
   python -m ingestion.load                     # newest feed -> logs_raw; bad lines -> rejected_records
   python -m detection.runner                   # dry run: detect + print
   python -m detection.runner --commit          # persist: mark processed, create alerts + incidents, log the run
   ```

6. **Weekly report:**

   ```
   python -m reports.weekly_report              # -> reports/out/weekly_<date>.html
   ```

7. **Dashboard** (needs a login — generate a password hash first):

   ```
   python -m dashboard.hash_password 'your password'   # paste the hash into DASHBOARD_AUTH_PASSWORD_HASH
   streamlit run dashboard/app.py
   ```

8. **Tests** (DB integration tests auto-skip if no database is reachable):

   ```
   pytest -q                 # everything
   pytest -m "not db" -q     # fast, offline
   ```

## Automation (GitHub Actions)

`.github/workflows/pipeline.yml` runs `pytest -m "not db"` then
simulate → ingest → detect (`--commit`) every 6 hours (and on demand). It needs
three repository secrets:

```
gh secret set DATABASE_URL     -R <owner>/<repo> --body 'postgresql+psycopg://OWNER:...'
gh secret set DATABASE_URL_RW  -R <owner>/<repo> --body 'postgresql+psycopg://sentrexa_rw:...'
gh secret set DATABASE_URL_RO  -R <owner>/<repo> --body 'postgresql+psycopg://sentrexa_ro:...'
```

(or *Settings → Secrets and variables → Actions* in the GitHub UI). The values
are the same connection strings the bootstrap wrote into `.env`.

## Deployment

The dashboard is read-only (`sentrexa_ro`) and gated by
`streamlit-authenticator`. HTTPS is provided by the platform.

**Streamlit Community Cloud** — connect the repo at
[share.streamlit.io](https://share.streamlit.io), set the entrypoint to
`dashboard/app.py`, and paste the keys from
`.streamlit/secrets.toml.example` into the *Secrets* box (real values).
`app.py` mirrors `st.secrets` into the environment so `config/settings.py`
picks them up.

**Render** — `render.yaml` is a ready blueprint; set `DATABASE_URL_RO` and the
`DASHBOARD_AUTH_*` vars as secret env vars in the Render dashboard.

## Security

- No hardcoded credentials — `.env` locally, GitHub Actions / platform secrets in CI/deploy.
- SQLAlchemy ORM / bound parameters only — no string-built SQL anywhere.
- Least-privilege roles: `sentrexa_ro` (SELECT only) for the dashboard & reports,
  `sentrexa_rw` (SELECT/INSERT/UPDATE, no DELETE, no DDL) for the pipeline.
- Malformed log lines are quarantined into `rejected_records`, never dropped or
  allowed to crash the pipeline.
- Login gate on the dashboard before deployment; password stored only as a
  bcrypt hash.
- Simulated usernames / IPs are treated as PII; external addresses are drawn
  only from RFC 5737 documentation ranges.

## License

MIT — see [LICENSE](LICENSE).
