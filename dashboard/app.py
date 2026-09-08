"""Sentrexa analyst dashboard (Streamlit) — "declassified terminal" UI.

Four views: live alert feed, incident board, log search, and analytics. All data
is read through the least-privilege read-only role; the login gate wraps ``main``.
Presentation lives in ``dashboard/ui.py`` — this module is data -> view wiring.

Run:
    streamlit run dashboard/app.py
"""

from __future__ import annotations

import os
import sys

# Streamlit Community Cloud runs this file with only dashboard/ on sys.path, not
# the repo root, so `from dashboard import ...` / `from config import ...` fail.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, time, timezone  # noqa: E402

import pandas as pd  # noqa: E402
import plotly.express as px  # noqa: E402
import streamlit as st  # noqa: E402

# On Streamlit Community Cloud, secrets arrive via st.secrets - mirror them into
# the environment so config.settings (env-driven) picks them up unchanged.
try:  # pragma: no cover - only on Streamlit Cloud
    for _k, _v in st.secrets.items():
        if isinstance(_v, str):
            os.environ.setdefault(_k, _v)
except Exception:
    pass

from dashboard import data, ui  # noqa: E402
from dashboard.auth import require_login  # noqa: E402

st.set_page_config(page_title="SENTREXA // SOC", page_icon="📟", layout="wide")
ui.inject_css()

RULE_TYPES = ["brute_force", "off_hours_login", "privilege_escalation"]


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _date_range_picker(label: str, days: int = 7):
    start_default, end_default = data.default_window(days)
    c1, c2 = st.columns(2)
    d1 = c1.date_input(f"{label} from", start_default.date())
    d2 = c2.date_input(f"{label} to", end_default.date())
    start = datetime.combine(d1, time.min, tzinfo=timezone.utc)
    end = datetime.combine(d2, time.max, tzinfo=timezone.utc)
    return start, end


def _ago(ts) -> str:
    if ts is None or pd.isna(ts):
        return "—"
    ts = pd.Timestamp(ts)
    if ts.tzinfo is None:
        ts = ts.tz_localize("UTC")
    secs = max((pd.Timestamp.now(tz="UTC") - ts).total_seconds(), 0)
    if secs < 90:
        return f"{int(secs)}s"
    if secs < 5400:
        return f"{int(secs // 60)}m"
    if secs < 172800:
        return f"{int(secs // 3600)}h"
    return f"{int(secs // 86400)}d"


def _posture(k: dict) -> str:
    opens = int(k.get("open_incidents", 0))
    if opens >= 5:
        return "critical"
    if opens >= 1:
        return "elevated"
    return "nominal"


def _clip(text, n: int = 118) -> str:
    text = "" if text is None else str(text)
    return text if len(text) <= n else text[: n - 1] + "…"


def _txt(v) -> str:
    """A displayable string, or an em-dash for null / NaN."""
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return "—"
    s = str(v).strip()
    return s or "—"


# --------------------------------------------------------------------------- #
# views
# --------------------------------------------------------------------------- #
def view_alert_feed() -> None:
    with st.sidebar:
        st.markdown('<div class="sx-navlabel">alert filters</div>', unsafe_allow_html=True)
        severities = st.multiselect("Severity", ui.SEVERITY_ORDER, default=[])
        rule_types = st.multiselect("Rule type", RULE_TYPES)
        statuses = st.multiselect("Status", ["New", "Acknowledged", "Dismissed"])
        limit = st.slider("Max rows", 50, 2000, 500, step=50)

    st.markdown('<div class="sx-navlabel">query window — triggered between</div>',
                unsafe_allow_html=True)
    start, end = _date_range_picker("Triggered", 14)

    df = data.load_alerts(severities, rule_types, statuses, start, end, limit)
    ui.section("Live Alerts", f"{len(df)} records / newest first")

    if df.empty:
        ui.empty_state("No matching alerts", "Adjust the filter parameters in the left panel.")
        return

    rows = []
    for _, r in df.iterrows():
        rows.append({
            "severity": r["severity"],
            "age": _ago(r["triggered_at"]),
            "technique": r["mitre_technique_id"],
            "rule": r["rule_type"],
            "src_ip": _txt(r["source_ip"]),
            "user": _txt(r["username"]),
            "status": r["alert_status"],
            "incident": f"INC-{int(r['incident_id']):04d}" if pd.notna(r["incident_id"]) else "—",
        })
    ui.record_table(
        rows,
        [
            ("severity", "SEV", "sev"),
            ("age", "AGE", "mono"),
            ("technique", "TECHNIQUE", "mono"),
            ("rule", "RULE", ""),
            ("src_ip", "SOURCE IP", "mono"),
            ("user", "PRINCIPAL", "dim"),
            ("status", "STATUS", ""),
            ("incident", "INCIDENT", "mono"),
        ],
        severity_key="severity",
    )

    st.markdown('<div class="sx-navlabel">contributing log trace</div>', unsafe_allow_html=True)
    alert_id = st.selectbox("Alert ID", df["alert_id"].tolist(), label_visibility="collapsed")
    logs = data.load_alert_logs(int(alert_id))
    ui.section("Log Trace", f"alert {alert_id} / {len(logs)} lines")
    if logs.empty:
        ui.empty_state("No linked log lines")
    else:
        ui.record_table(
            [
                {
                    "ts": r["timestamp"].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "src": r["source_system"],
                    "evt": r["event_type"],
                    "status": r["status"],
                    "ip": _txt(r["source_ip"]),
                    "raw": _clip(r["raw_message"]),
                }
                for _, r in logs.iterrows()
            ],
            [
                ("ts", "TIMESTAMP", "mono"),
                ("src", "SOURCE", ""),
                ("evt", "EVENT", ""),
                ("status", "STATUS", ""),
                ("ip", "SOURCE IP", "mono"),
                ("raw", "RAW MESSAGE", "dim"),
            ],
        )


def view_incident_board() -> None:
    dfi = data.load_incidents()
    counts = {s: int((dfi["incident_status"] == s).sum()) for s in ["Open", "In Review", "Closed"]} if not dfi.empty else {}
    ui.section(
        "Incident Queue",
        f"{counts.get('Open', 0)} open / {counts.get('In Review', 0)} in review / {counts.get('Closed', 0)} closed",
    )
    if dfi.empty:
        ui.empty_state("Incident queue empty", "No alert has escalated to an incident.")
        return

    for status in ["Open", "In Review", "Closed"]:
        sub = dfi[dfi["incident_status"] == status]
        if sub.empty:
            continue
        st.markdown(f'<div class="sx-navlabel">{status} — {len(sub)}</div>', unsafe_allow_html=True)
        for _, row in sub.iterrows():
            ip = row.source_ip if isinstance(row.source_ip, str) else None
            user = row.username if isinstance(row.username, str) else None
            _, token = ui.SEVERITY_TOKENS.get(str(row.severity).lower(), ("", str(row.severity).upper()))
            label = f"INC-{int(row.incident_id):04d}   [{token.strip()}]   {row.rule_name}"
            with st.expander(label):
                st.markdown(ui.severity_badge(row.severity), unsafe_allow_html=True)
                ui.fields([
                    ("Alert", f"{int(row.alert_id)}  ({row.alert_status})", True),
                    ("Triggered", f"{row.triggered_at:%Y-%m-%dT%H:%M:%SZ}", True),
                    ("Opened", f"{row.opened_at:%Y-%m-%dT%H:%M:%SZ}", True),
                    ("Age", f"{row.age_hours:.1f} h", True),
                    ("Origin", ip or user or "—", True),
                    ("MITRE", f"{row.technique_name}  /  {row.tactic}", False),
                    ("Assigned", _txt(row.assigned_to) if _txt(row.assigned_to) != "—" else "(unassigned)", False),
                    ("Resolution", _txt(row.resolution_notes), False),
                ])
    st.caption("status changes require an authenticated write session")


def view_log_search() -> None:
    ui.section("Log Search", "raw normalized event store")
    c1, c2, c3 = st.columns(3)
    source = c1.selectbox("Source", ["(any)", "auth", "web", "firewall"])
    event_type = c2.selectbox(
        "Event type", ["(any)", "login", "logout", "sudo", "http_request", "connection"]
    )
    status = c3.selectbox("Status", ["(any)", "success", "failure", "allowed", "blocked"])
    needle = st.text_input("Contains (raw message / username / IP)")
    start, end = _date_range_picker("Time", 14)
    limit = st.slider("Max rows", 50, 5000, 500, step=50, key="logsearch_limit")

    df = data.load_logs(source, event_type, status, needle or None, start, end, limit)
    ui.section("Results", f"{len(df)} lines")
    if df.empty:
        ui.empty_state("No matching log lines", "Broaden the query or the time window.")
        return
    ui.record_table(
        [
            {
                "ts": r["timestamp"].strftime("%Y-%m-%dT%H:%M:%SZ"),
                "src": r["source_system"],
                "evt": r["event_type"],
                "status": r["status"],
                "ip": _txt(r["source_ip"]),
                "user": _txt(r["username"]),
                "raw": _clip(r["raw_message"]),
            }
            for _, r in df.iterrows()
        ],
        [
            ("ts", "TIMESTAMP", "mono"),
            ("src", "SOURCE", ""),
            ("evt", "EVENT", ""),
            ("status", "STATUS", ""),
            ("ip", "SOURCE IP", "mono"),
            ("user", "PRINCIPAL", "dim"),
            ("raw", "RAW MESSAGE", "dim"),
        ],
    )


def _chart(fig, **kw) -> None:
    st.plotly_chart(ui.style_fig(fig, **kw), width="stretch",
                    config={"displayModeBar": False})


_MONO_SERIES = [ui.PALETTE["caution"]]        # single-series utilitarian fill
_SEQ = ui.CHART_SEQUENCE


def view_analytics() -> None:
    ui.section("Analytics", "aggregate threat picture")

    left, right = st.columns(2)
    with left:
        sev = data.alerts_by_severity()
        if sev.empty:
            ui.empty_state("No alerts to aggregate")
        else:
            _chart(px.bar(
                sev, x="severity", y="n", color="severity",
                color_discrete_map=ui.SEVERITY_CHART_COLORS,
                category_orders={"severity": ui.SEVERITY_ORDER},
                title="ALERTS BY SEVERITY",
            ), legend=False)
        ips = data.top_source_ips(10)
        if not ips.empty:
            _chart(px.bar(ips, x="alerts", y="source_ip", orientation="h",
                          color_discrete_sequence=_MONO_SERIES,
                          title="TOP OFFENDING SOURCE IPS"),
                   horizontal=True, legend=False)

    with right:
        tac = data.alerts_by_tactic()
        if not tac.empty:
            tac = tac.assign(technique_name=tac["technique_name"].str.slice(0, 24))
            _chart(px.bar(tac, x="n", y="technique_name", color="tactic",
                          color_discrete_sequence=_SEQ, orientation="h",
                          title="ALERTS BY MITRE TECHNIQUE"),
                   horizontal=True)
        users = data.top_usernames(10)
        if not users.empty:
            _chart(px.bar(users, x="alerts", y="username", orientation="h",
                          color_discrete_sequence=_MONO_SERIES,
                          title="TOP ALERTED PRINCIPALS"),
                   horizontal=True, legend=False)

    ot = data.alerts_over_time()
    if not ot.empty:
        _chart(px.line(ot, x="day", y="n", color="severity",
                       color_discrete_map=ui.SEVERITY_CHART_COLORS, markers=True,
                       title="ALERTS OVER TIME"), height=280)

    runs = data.run_log(40)
    ui.section("Detection Run Log", f"last {len(runs)} runs")
    if runs.empty:
        ui.empty_state("No pipeline runs recorded")
    else:
        ui.record_table(
            [
                {
                    "run": int(r["run_id"]),
                    "ts": pd.Timestamp(r["run_timestamp"]).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "stage": r["stage"],
                    "logs": int(r["logs_processed"]),
                    "alerts": int(r["alerts_generated"]),
                    "status": r["status"],
                    "ms": "—" if pd.isna(r["duration_ms"]) else int(r["duration_ms"]),
                }
                for _, r in runs.iterrows()
            ],
            [
                ("run", "RUN", "mono"),
                ("ts", "TIMESTAMP", "mono"),
                ("stage", "STAGE", ""),
                ("logs", "LOGS", "num"),
                ("alerts", "ALERTS", "num"),
                ("status", "STATUS", ""),
                ("ms", "MS", "num"),
            ],
        )


VIEWS = {
    "Live Alerts": view_alert_feed,
    "Incidents": view_incident_board,
    "Log Search": view_log_search,
    "Analytics": view_analytics,
}


# --------------------------------------------------------------------------- #
# entrypoint
# --------------------------------------------------------------------------- #
def main() -> None:
    with st.sidebar:
        st.markdown(
            '<div class="sx-wordmark">SENTREXA<small>SOC // TERMINAL</small></div>',
            unsafe_allow_html=True,
        )

    name = require_login()  # renders login form + st.stop() until authenticated

    with st.sidebar:
        st.markdown(
            f'<div class="sx-operator">operator // <b>{name}</b></div>',
            unsafe_allow_html=True,
        )
        st.markdown('<div class="sx-navlabel">sections</div>', unsafe_allow_html=True)
        choice = st.radio("nav", list(VIEWS), label_visibility="collapsed")

    k = data.kpis()
    ui.banner()
    ui.identity(_posture(k))
    ui.subline(f"live feed — synchronised {ui.now_stamp()}")
    ui.ledger([
        ("Total Alerts", f"{int(k['total_alerts'])}", "all time", ""),
        ("Unreviewed", f"{int(k['new_alerts'])}", "status new", ""),
        ("Severity High+", f"{int(k['high_alerts'])}", "escalation path", "accent"),
        ("Open Incidents", f"{int(k['open_incidents'])}", "unresolved", "warn"),
        ("Logs Ingested", f"{int(k['total_logs'])}", "normalized", ""),
        ("Quarantined", f"{int(k['rejected_logs'])}", "rejected lines", ""),
    ])

    VIEWS[choice]()


if __name__ == "__main__":
    main()
