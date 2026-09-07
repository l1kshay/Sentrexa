"""Sentrexa analyst dashboard (Streamlit).

Four views: live alert feed, incident board, log search, and analytics. All data
is read through the least-privilege read-only role. The login gate is added in
Phase 6 (streamlit-authenticator wraps ``main``).

Run:
    streamlit run dashboard/app.py
"""

from __future__ import annotations

from datetime import datetime, time, timezone

import plotly.express as px
import streamlit as st

from dashboard import data

st.set_page_config(page_title="Sentrexa SOC", page_icon="🛡️", layout="wide")

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_COLORS = {
    "critical": "#7f1d1d", "high": "#dc2626", "medium": "#f59e0b", "low": "#3b82f6",
}


def _date_range_picker(label: str, days: int = 7):
    start_default, end_default = data.default_window(days)
    c1, c2 = st.columns(2)
    d1 = c1.date_input(f"{label} from", start_default.date())
    d2 = c2.date_input(f"{label} to", end_default.date())
    start = datetime.combine(d1, time.min, tzinfo=timezone.utc)
    end = datetime.combine(d2, time.max, tzinfo=timezone.utc)
    return start, end


# --------------------------------------------------------------------------- #
# Views
# --------------------------------------------------------------------------- #
def view_alert_feed() -> None:
    st.header("Live alert feed")

    with st.sidebar:
        st.subheader("Filters")
        severities = st.multiselect("Severity", SEVERITY_ORDER, default=[])
        rule_types = st.multiselect(
            "Rule type", ["brute_force", "off_hours_login", "privilege_escalation"]
        )
        statuses = st.multiselect("Status", ["New", "Acknowledged", "Dismissed"])
        limit = st.slider("Max rows", 50, 2000, 500, step=50)
    start, end = _date_range_picker("Triggered", 14)

    df = data.load_alerts(severities, rule_types, statuses, start, end, limit)
    st.caption(f"{len(df)} alert(s)")
    st.dataframe(
        df.drop(columns=["alert_id"]),
        width="stretch",
        hide_index=True,
    )

    if not df.empty:
        alert_id = st.selectbox(
            "Inspect contributing logs for alert", df["alert_id"].tolist()
        )
        logs = data.load_alert_logs(int(alert_id))
        st.write(f"**{len(logs)} contributing log line(s)**")
        st.dataframe(logs, width="stretch", hide_index=True)


def view_incident_board() -> None:
    st.header("Incident board")
    dfi = data.load_incidents()
    if dfi.empty:
        st.info("No incidents yet.")
        return

    cols = st.columns(3)
    for col, status in zip(cols, ["Open", "In Review", "Closed"]):
        sub = dfi[dfi["incident_status"] == status]
        col.metric(status, len(sub))

    for status in ["Open", "In Review", "Closed"]:
        sub = dfi[dfi["incident_status"] == status]
        if sub.empty:
            continue
        st.subheader(f"{status} ({len(sub)})")
        for _, row in sub.iterrows():
            title = (
                f"#{row.incident_id} · {row.severity.upper()} · {row.rule_name} · "
                f"{row.source_ip or row.username or '-'} · age {row.age_hours:.1f}h"
            )
            with st.expander(title):
                st.write(
                    f"**Alert** {row.alert_id} ({row.alert_status}) — "
                    f"triggered {row.triggered_at:%Y-%m-%d %H:%M} UTC"
                )
                st.write(f"**MITRE** {row.technique_name} · {row.tactic}")
                st.write(f"**Assigned to** {row.assigned_to or '(unassigned)'}")
                if row.resolution_notes:
                    st.write(f"**Resolution** {row.resolution_notes}")
    st.caption("Status changes require the analyst login gate (Phase 6).")


def view_log_search() -> None:
    st.header("Log search")
    c1, c2, c3 = st.columns(3)
    source = c1.selectbox("Source", ["(any)", "auth", "web", "firewall"])
    event_type = c2.selectbox(
        "Event type",
        ["(any)", "login", "logout", "sudo", "http_request", "connection"],
    )
    status = c3.selectbox(
        "Status", ["(any)", "success", "failure", "allowed", "blocked"]
    )
    needle = st.text_input("Contains (raw message / username / IP)")
    start, end = _date_range_picker("Time", 14)
    limit = st.slider("Max rows", 50, 5000, 500, step=50, key="logsearch_limit")

    df = data.load_logs(source, event_type, status, needle or None, start, end, limit)
    st.caption(f"{len(df)} log line(s)")
    st.dataframe(df, width="stretch", hide_index=True)


def view_analytics() -> None:
    st.header("Analytics")

    k = data.kpis()
    c = st.columns(6)
    c[0].metric("Alerts", int(k["total_alerts"]))
    c[1].metric("New", int(k["new_alerts"]))
    c[2].metric("High/critical", int(k["high_alerts"]))
    c[3].metric("Open incidents", int(k["open_incidents"]))
    c[4].metric("Logs", int(k["total_logs"]))
    c[5].metric("Quarantined", int(k["rejected_logs"]))

    left, right = st.columns(2)

    with left:
        sev = data.alerts_by_severity()
        if not sev.empty:
            fig = px.bar(
                sev, x="severity", y="n", color="severity",
                color_discrete_map=SEVERITY_COLORS,
                category_orders={"severity": SEVERITY_ORDER},
                title="Alerts by severity",
            )
            st.plotly_chart(fig, width="stretch")

        ips = data.top_source_ips(10)
        if not ips.empty:
            st.plotly_chart(
                px.bar(ips, x="alerts", y="source_ip", orientation="h",
                       title="Top offending source IPs"),
                width="stretch",
            )

    with right:
        tac = data.alerts_by_tactic()
        if not tac.empty:
            st.plotly_chart(
                px.bar(tac, x="n", y="technique_name", color="tactic",
                       orientation="h", title="Alerts by MITRE technique"),
                width="stretch",
            )

        users = data.top_usernames(10)
        if not users.empty:
            st.plotly_chart(
                px.bar(users, x="alerts", y="username", orientation="h",
                       title="Top alerted usernames"),
                width="stretch",
            )

    ot = data.alerts_over_time()
    if not ot.empty:
        st.plotly_chart(
            px.line(ot, x="day", y="n", color="severity",
                    color_discrete_map=SEVERITY_COLORS, markers=True,
                    title="Alerts over time"),
            width="stretch",
        )

    st.subheader("Detection run history")
    st.dataframe(data.run_log(50), width="stretch", hide_index=True)


VIEWS = {
    "Alert feed": view_alert_feed,
    "Incident board": view_incident_board,
    "Log search": view_log_search,
    "Analytics": view_analytics,
}


def main() -> None:
    st.sidebar.title("🛡️ Sentrexa SOC")
    choice = st.sidebar.radio("View", list(VIEWS))
    st.sidebar.divider()
    VIEWS[choice]()
    st.sidebar.caption("Read-only role · data refreshes every 60s")


if __name__ == "__main__":
    main()
