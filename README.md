# Sentrexa

**SOC-style log monitoring & alerting dashboard, with a BI & cloud-analytics layer.**

Sentrexa is a simulated Security Operations Center (SOC) monitoring system. It
generates realistic synthetic logs (auth / web / firewall) with deliberately
seeded attack scenarios, normalizes them into PostgreSQL, runs a configurable
**rule-based** (non-ML) detection engine, converts qualifying detections into
severity-tagged alerts mapped to MITRE ATT&CK, auto-escalates high-severity
alerts into incident tickets, and surfaces everything through a Streamlit
analyst dashboard plus a weekly report. A later phase syncs a denormalized copy
of the alert/incident data into Google BigQuery for three independent BI
dashboards (Looker Studio, Power BI, Tableau).

## Status

| Phase | Scope | State |
|------:|-------|-------|
| 1 | Log simulation foundation | in progress |
| 2 | Ingestion & storage (PostgreSQL) | not started |
| 3 | Detection engine | not started |
| 4 | Alerting, ticketing & MITRE mapping | not started |
| 5 | Dashboard & reporting | not started |
| 6 | Automation, security & deployment | not started |
| 7 | BI & cloud analytics (BigQuery + 3 BI tools) | not started (gated on Phase 6) |

## Tech stack

Python · Streamlit · PostgreSQL · SQLAlchemy · Faker · Pandas · Plotly ·
Jinja2 · streamlit-authenticator · pytest · GitHub Actions · (Phase 7) Google
BigQuery + Looker Studio / Power BI / Tableau.

## Repository layout

```
simulation/        synthetic log generators + seeded attack scenarios
ingestion/         parse + normalize + load into PostgreSQL (quarantine rejects)
detection/         config-driven rule engine (rules live in the DB, not code)
mitre/             curated static MITRE ATT&CK reference table
alerting/          alert generation + incident escalation + status workflows
dashboard/         Streamlit analyst UI (auth-gated)
reports/           Jinja2 weekly summary report
bi_export/         (Phase 7) watermark-based incremental sync to BigQuery
sql/               schema DDL + reusable queries
config/            centralized settings (config/settings.py)
tests/             pytest suite, focused on the detection rule engine
.github/workflows/ pipeline.yml (core cycle) + bigquery_sync.yml (Phase 7)
```

## Local setup

1. **Python 3.14** and a PostgreSQL database (local or hosted, e.g. Neon).
2. `python -m pip install -r requirements.txt`
3. `cp .env.example .env` and fill in real values. `.env` is gitignored; never
   commit real credentials.
4. Phase 1 (simulation) needs no database:

   ```
   python -m simulation.dataset            # writes data/raw/<timestamp>.ndjson + .scenarios.json
   pytest tests/test_simulation.py -q
   ```

Later phases add database bootstrap, the detection cycle, and the dashboard;
their commands will be documented here as they land.

## Security notes

- No hardcoded credentials — secrets in `.env` locally, GitHub Actions secrets in CI.
- Parameterized / ORM queries only.
- Least-privilege DB roles: read-only for the dashboard, read/write for ingestion & detection.
- Malformed log entries are quarantined, never silently dropped.
- Simulated usernames / IPs are treated as if they were real PII.

## License

MIT — see [LICENSE](LICENSE).
