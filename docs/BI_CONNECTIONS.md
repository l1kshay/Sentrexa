# Connecting BI tools to the Sentrexa BigQuery dataset

Looker Studio, Power BI, and Tableau each connect **read-only** to BigQuery
using **"Sign in with Google" (OAuth)** with a project-Owner account — no reader
service account and no key file. Common values:

* **Billing / query project:** `sentrexa`
* **Dataset:** `analytics`
* **Tables:** `fact_alerts`, `fact_logs_daily`, `dim_mitre_techniques`, `dim_detection_rules`

## 1 — Looker Studio (shareable public link)

1. [lookerstudio.google.com](https://lookerstudio.google.com) → **Create → Data source**.
2. Pick the **BigQuery** connector (by Google) → **Authorize** with your Google account.
3. **My Projects → `sentrexa` → `analytics` → `fact_alerts` → Connect**. Add
   `fact_logs_daily` as a second data source the same way.
4. **Add to report.** Suggested tiles:
   * Scorecards: `Record Count` (alerts); `incident_id` (COUNT DISTINCT, filter `incident_status = "Open"`); `resolution_hours` (AVG → "mean time to resolve").
   * Time series: dimension `triggered_at` (by day), metric `Record Count`, breakdown `severity`.
   * Bar: dimension `tactic` (or `technique_name`), metric `Record Count`.
   * Table: dimension `source_ip`, metric `Record Count`, sorted desc.
   * From `fact_logs_daily`: stacked column, dimension `log_date`, metric `event_count`, breakdown `source_system`.
5. **Share → Manage access → Anyone with the link → Viewer** for the portfolio link.

## 2 — Power BI Desktop (import mode, ≥1 DAX measure + drill-through)

1. **Home → Get data → More… → Database → Google BigQuery → Connect**.
2. Leave *Billing Project ID* = `sentrexa` (or blank) → **OK**.
3. **Sign in → Sign in with Google →** your Owner account → **Connect**.
4. **Navigator:** expand `sentrexa → analytics`, tick `fact_alerts`,
   `fact_logs_daily`, `dim_mitre_techniques`, `dim_detection_rules` → **Load**
   (Import; DirectQuery also works).
5. **Model view:** create relationships if not auto-detected —
   `fact_alerts[rule_id] → dim_detection_rules[rule_id]` and
   `fact_alerts[mitre_technique_id] → dim_mitre_techniques[technique_id]`, both
   many-to-one, single cross-filter.
6. **DAX measures** (New measure):
   ```DAX
   Mean Time To Resolve (h) = AVERAGE ( fact_alerts[resolution_hours] )

   Open Incidents =
   CALCULATE ( DISTINCTCOUNT ( fact_alerts[incident_id] ),
               fact_alerts[incident_status] = "Open" )

   High-Severity Rate =
   DIVIDE (
       CALCULATE ( COUNTROWS ( fact_alerts ),
                   fact_alerts[severity] IN { "high", "critical" } ),
       COUNTROWS ( fact_alerts )
   )
   ```
7. **Drill-through:** add a page named **Alert detail** with a table of
   `alert_id, triggered_at, severity, rule_name, technique_name, source_ip,
   username, incident_status, resolution_hours`. In the *Visualizations → Drill
   through* well drop `mitre_technique_id` (or `rule_name`). On a summary page,
   right-click a bar → **Drill through → Alert detail**.
8. Optionally **Publish** to the Power BI service.

## 3 — Tableau (Public) — time-of-day attack heatmap (deliberately distinct)

1. **Connect → To a Server → Google BigQuery**.
2. **Authentication: Sign In with OAuth →** your Google account → **Allow**.
3. *Billing Project* = `sentrexa`, *Project* = `sentrexa`, *Dataset* = `analytics`.
4. Drag **`fact_alerts`** to the canvas (no join needed — it's denormalized).
5. Create calculated fields:
   ```
   Hour of Day  =  DATEPART('hour', [Triggered At])
   Day of Week  =  DATENAME('weekday', [Triggered At])
   ```
6. Build the heatmap:
   * **Columns:** `Hour of Day` (Discrete, 0–23)
   * **Rows:** `Day of Week` (Discrete; sort Monday→Sunday)
   * **Marks:** type **Square**; **Color** = `CNT(Alert Id)`; **Label** = `CNT(Alert Id)`
   * Optional shelf filters: `Severity`, `Rule Type`
   * A sequential colour ramp makes the night-time brute-force and off-hours-login
     clusters obvious at a glance.
7. Add a companion sheet if you like: bar of `CNT(Alert Id)` by `Tactic`, or a
   line of `SUM(Event Count)` by `Log Date` from `fact_logs_daily`.
8. **Server → Tableau Public → Save** for the portfolio link.

> `source_ip` values are RFC 5737 documentation addresses (not geolocatable), so
> the time-of-day heatmap is the meaningful "distinct" visual rather than a geo map.
