"""Presentation layer for the Sentrexa dashboard — "declassified terminal".

Everything visual lives here so ``app.py`` stays about wiring data to views:

* ``PALETTE`` / ``CHART_TEMPLATE`` - the shared colour + Plotly language.
* ``inject_css()`` - ONE consolidated <style> block (fonts + config-theme
  overrides + component restyles + the ``sx-*`` helper classes). Call once,
  right after ``st.set_page_config``.
* small render helpers (``banner``, ``ledger``, ``section``, ``severity_badge``,
  ``record_table``, ``empty_state``) that emit ``st.markdown`` fragments using
  those classes.
* ``style_fig()`` - apply the palette to any Plotly figure.

No data access, no business logic.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

import streamlit as st

# --------------------------------------------------------------------------- #
# Palette
# --------------------------------------------------------------------------- #
PALETTE = {
    "bg": "#0C0C0C",
    "bg_raised": "#141414",
    "bg_inset": "#1C1C1C",
    "rule": "#3A3A3A",
    "rule_strong": "#5A5A5A",
    "fg": "#E4E1D8",
    "fg_dim": "#9A968B",
    "fg_faint": "#63605A",
    "stamp": "#C8402F",     # CRITICAL, classification, focus, destructive
    "caution": "#C98A2B",   # HIGH, in-review, warnings, links
    "confirm": "#6E8E6A",   # resolved / closed / nominal
}

# severity name -> badge modifier + display token (padded for mono alignment)
SEVERITY_TOKENS = {
    "critical": ("crit", "CRIT"),
    "high": ("high", "HIGH"),
    "medium": ("med", "MED "),
    "low": ("low", "LOW "),
}
SEVERITY_ORDER = ["critical", "high", "medium", "low"]

# Plotly colourway + per-severity colour (charts must speak the same language)
CHART_SEQUENCE = [
    PALETTE["stamp"], PALETTE["caution"], PALETTE["fg"],
    PALETTE["confirm"], PALETTE["fg_faint"], PALETTE["fg_dim"],
]
SEVERITY_CHART_COLORS = {
    "critical": PALETTE["stamp"],
    "high": PALETTE["caution"],
    "medium": PALETTE["fg"],
    "low": PALETTE["fg_dim"],
}

_FONT = "'IBM Plex Mono', ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace"


# --------------------------------------------------------------------------- #
# The one consolidated CSS block
# --------------------------------------------------------------------------- #
def _root_vars() -> str:
    return ";".join(f"--{k.replace('_', '-')}:{v}" for k, v in PALETTE.items())


_CSS = f"""
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&display=swap');

:root {{ {_root_vars()}; }}

/* ---- reset / ground ---------------------------------------------------- */
html, body, .stApp,
[data-testid="stAppViewContainer"], [data-testid="stHeader"] {{
    background: var(--bg) !important;
    color: var(--fg);
}}
[data-testid="stHeader"] {{ border-bottom: 1px solid var(--rule); height: 0; }}

/* Square everything. Set the mono face only on semantic text containers -
   bare span / i / button carry Streamlit's Material icon ligatures, so we
   must NOT override their font-family. */
* {{ border-radius: 0 !important; }}
html, body, .stApp,
.stMarkdown, .stMarkdown p, .stMarkdown span, .stMarkdown li, .stMarkdown a,
.stMarkdown div, h1, h2, h3, h4, h5, td, th, code, pre, kbd,
.sx-tablewrap, .sx-tablewrap *,
[data-testid="stWidgetLabel"], [data-testid="stWidgetLabel"] *,
[data-testid="stMarkdownContainer"], [data-testid="stMarkdownContainer"] *,
[data-testid="stText"], [data-testid="stMetricValue"], [data-testid="stMetricLabel"],
input, textarea, [data-baseweb="input"] *, [data-baseweb="select"] div,
[data-baseweb="tab"] *, [role="radiogroup"] label *, [role="option"],
.stButton button, .stSlider [data-testid="stTickBar"] {{
    font-family: {_FONT};
}}
/* belt & braces: never let the mono face reach an icon ligature */
[data-testid="stIconMaterial"], [class*="material-symbols"], [class*="material-icons"],
i[class*="material"], span[class*="material"] {{
    font-family: 'Material Symbols Rounded','Material Symbols Outlined','Material Icons' !important;
}}
::selection {{ background: var(--stamp); color: #000; }}
a, a:visited {{ color: var(--caution); text-decoration: underline; text-underline-offset: 2px; }}

[data-testid="stMainBlockContainer"], .block-container {{
    padding: 0 2.75rem 4rem !important; max-width: 1500px;
}}
[data-testid="stAppViewContainer"] > .main {{ background: var(--bg); }}

/* ---- typography ------------------------------------------------------- */
h1, h2, h3, h4, h5 {{
    font-family: {_FONT} !important; color: var(--fg);
    letter-spacing: .01em; font-weight: 600;
}}
h1 {{ font-size: 1.35rem; text-transform: uppercase; letter-spacing: .12em; }}
h2 {{ font-size: 1.05rem; }}
p, span, label, li, div {{ font-size: .8125rem; }}
[data-testid="stCaptionContainer"], .stCaption, small {{
    color: var(--fg-faint) !important; font-size: .6875rem !important;
    letter-spacing: .08em; text-transform: uppercase;
}}
hr {{ border: none; border-top: 1px solid var(--rule); margin: 1.25rem 0; }}
code, pre, kbd, [data-testid="stCode"] {{
    background: var(--bg-inset) !important; color: var(--fg) !important;
    border: 1px solid var(--rule); font-family: {_FONT} !important;
}}

/* ---- sidebar : control panel --------------------------------------- */
[data-testid="stSidebar"] {{
    background: var(--bg) !important;
    border-right: 2px solid var(--rule-strong);
}}
[data-testid="stSidebar"] [data-testid="stSidebarUserContent"] {{ padding: 1.1rem 1.1rem 2rem; }}
[data-testid="stSidebar"] p, [data-testid="stSidebar"] span,
[data-testid="stSidebar"] label, [data-testid="stSidebar"] div {{ font-size: .75rem; }}
[data-testid="stSidebar"] [data-testid="stWidgetLabel"] p {{
    text-transform: uppercase; letter-spacing: .12em; font-size: .62rem;
    color: var(--fg-dim); font-weight: 500;
}}
[data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 {{
    font-size: .7rem !important; letter-spacing: .16em; text-transform: uppercase;
    color: var(--fg-dim); font-weight: 600; margin: 1.4rem 0 .5rem;
}}

/* nav radio -> terminal menu */
[data-testid="stSidebar"] [role="radiogroup"] {{ gap: 0 !important; }}
[data-testid="stSidebar"] [role="radiogroup"] label {{
    padding: .5rem .6rem; margin: 0 !important; border-left: 3px solid transparent;
    text-transform: uppercase; letter-spacing: .1em; color: var(--fg-dim);
    cursor: pointer; transition: none;
}}
[data-testid="stSidebar"] [role="radiogroup"] label:hover {{ color: var(--fg); background: var(--bg-inset); }}
/* collapse the radio dot but keep it clickable (display:none breaks selection) */
[data-testid="stSidebar"] [role="radiogroup"] label > div:first-child {{
    width: 0 !important; height: 0 !important; min-width: 0 !important;
    overflow: hidden; margin: 0 !important; padding: 0 !important; border: 0 !important;
}}
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {{
    color: var(--fg); border-left-color: var(--stamp);
    background: var(--bg-inset); font-weight: 600;
}}
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) div p::before {{ content: "\\25B8  "; color: var(--stamp); }}
[data-testid="stSidebar"] [role="radiogroup"] label div p::before {{ content: "\\2007\\2007  "; }}

/* ---- widgets : square, de-chromed --------------------------------- */
[data-baseweb="input"], [data-baseweb="select"] > div, [data-baseweb="textarea"],
.stMultiSelect > div > div, [data-testid="stDateInput"] input {{
    background: var(--bg-inset) !important; border: 1px solid var(--rule) !important;
    color: var(--fg) !important; box-shadow: none !important;
}}
[data-baseweb="input"]:focus-within, [data-baseweb="select"] > div:focus-within,
.stMultiSelect > div > div:focus-within {{
    border-color: var(--stamp) !important; outline: 1px solid var(--stamp);
}}
input, textarea, [data-baseweb="select"] div {{ color: var(--fg) !important; font-family: {_FONT} !important; }}
[data-baseweb="tag"] {{
    background: var(--bg) !important; border: 1px solid var(--caution) !important;
    color: var(--caution) !important;
}}
[data-baseweb="popover"], [data-baseweb="menu"], [role="listbox"] {{
    background: var(--bg-raised) !important; border: 1px solid var(--rule-strong) !important;
}}
[role="option"]:hover, [role="option"][aria-selected="true"] {{ background: var(--bg-inset) !important; }}

.stButton > button, .stDownloadButton > button {{
    background: transparent !important; border: 1px solid var(--rule-strong) !important;
    color: var(--fg) !important; text-transform: uppercase; letter-spacing: .1em;
    font-size: .7rem; padding: .45rem 1rem; box-shadow: none !important;
}}
.stButton > button:hover {{ border-color: var(--stamp) !important; color: var(--stamp) !important; }}

.stSlider [data-baseweb="slider"] div[role="slider"] {{ background: var(--stamp) !important; border-radius: 0 !important; }}
.stSlider [data-baseweb="slider"] > div > div {{ background: var(--rule-strong) !important; }}
.stSlider [data-baseweb="slider"] > div > div > div {{ background: var(--stamp) !important; }}

/* ---- metric fallback (should be replaced by the ledger) --------- */
[data-testid="stMetric"] {{ background: var(--bg-raised); border: 1px solid var(--rule); padding: .8rem 1rem; }}
[data-testid="stMetricValue"] {{ font-weight: 700; }}
[data-testid="stMetricLabel"] {{ text-transform: uppercase; letter-spacing: .12em; color: var(--fg-dim); }}

/* ---- expander : incident dossier -------------------------------- */
[data-testid="stExpander"] {{ background: var(--bg-raised); border: 1px solid var(--rule) !important; margin-bottom: -1px; }}
[data-testid="stExpander"] summary {{ font-family: {_FONT} !important; color: var(--fg); }}
[data-testid="stExpander"] summary:hover {{ color: var(--stamp); }}

/* ---- alerts / toasts ----------------------------------------------- */
[data-testid="stAlert"] {{
    background: var(--bg-inset) !important; border: 1px solid var(--rule-strong) !important;
    border-left: 3px solid var(--caution) !important; color: var(--fg) !important;
}}

/* ---- dataframe / chart panels ----------------------------------- */
[data-testid="stDataFrame"] {{ border: 1px solid var(--rule); }}
[data-testid="stPlotlyChart"] {{ border: 1px solid var(--rule); background: var(--bg); margin-bottom: -1px; }}
.js-plotly-plot .plotly .modebar {{ display: none !important; }}

/* ---- scrollbars -------------------------------------------------- */
::-webkit-scrollbar {{ width: 10px; height: 10px; }}
::-webkit-scrollbar-track {{ background: var(--bg); }}
::-webkit-scrollbar-thumb {{ background: var(--rule); border: 2px solid var(--bg); }}
::-webkit-scrollbar-thumb:hover {{ background: var(--rule-strong); }}

/* =================================================================== */
/*  sx-* : custom fragments                                             */
/* =================================================================== */
.sx-banner {{
    border-top: 2px solid var(--stamp); border-bottom: 1px solid var(--rule);
    background: repeating-linear-gradient(45deg, var(--bg) 0 12px, #111 12px 24px);
    padding: .4rem 0; margin: 0 -2.75rem 1.4rem;
    text-align: center; font-size: .65rem; letter-spacing: .28em;
    text-transform: uppercase; color: var(--fg-dim);
}}
.sx-banner b {{ color: var(--stamp); }}

.sx-ident {{ display: flex; align-items: baseline; gap: 1rem; margin-bottom: .2rem; }}
.sx-ident h1 {{ margin: 0; font-size: 1.5rem; letter-spacing: .18em; }}
.sx-ident .tick {{ color: var(--stamp); font-size: 1.5rem; line-height: 1; }}
.sx-ident .posture {{
    margin-left: auto; font-size: .7rem; letter-spacing: .16em; padding: .2rem .6rem;
    border: 1px solid currentColor;
}}
.sx-posture-nominal {{ color: var(--confirm); }}
.sx-posture-elevated {{ color: var(--caution); }}
.sx-posture-critical {{ color: var(--stamp); }}
.sx-subline {{ color: var(--fg-faint); font-size: .68rem; letter-spacing: .12em; text-transform: uppercase; margin-bottom: 1.2rem; }}
.sx-subline .live::before {{ content: "\\25CF"; color: var(--confirm); margin-right: .4rem; }}

/* KPI ledger */
.sx-ledger {{
    display: grid; grid-template-columns: repeat(var(--cols, 4), 1fr);
    border: 1px solid var(--rule-strong); background: var(--bg-raised); margin-bottom: 2rem;
}}
.sx-cell {{ padding: 1rem 1.15rem 1.05rem; border-left: 1px solid var(--rule); }}
.sx-cell:first-child {{ border-left: none; }}
.sx-cell .lbl {{ font-size: .625rem; letter-spacing: .16em; text-transform: uppercase; color: var(--fg-dim); }}
.sx-cell .val {{ font-size: 3rem; font-weight: 700; line-height: 1.05; letter-spacing: -.03em; font-feature-settings: "tnum"; }}
.sx-cell .note {{ font-size: .625rem; letter-spacing: .1em; text-transform: uppercase; color: var(--fg-faint); }}
.sx-cell.accent .val {{ color: var(--stamp); }}
.sx-cell.warn   .val {{ color: var(--caution); }}

/* section header */
.sx-sec {{
    display: flex; align-items: baseline; justify-content: space-between;
    border-bottom: 2px solid var(--rule-strong); padding-bottom: .3rem; margin: 1.6rem 0 .9rem;
}}
.sx-sec .name {{ font-size: .75rem; letter-spacing: .2em; text-transform: uppercase; color: var(--fg); }}
.sx-sec .name::before {{ content: "[ "; color: var(--fg-faint); }}
.sx-sec .name::after  {{ content: " ]"; color: var(--fg-faint); }}
.sx-sec .meta {{ font-size: .65rem; letter-spacing: .12em; text-transform: uppercase; color: var(--fg-dim); font-feature-settings: "tnum"; }}

/* severity badge */
.sx-badge {{
    display: inline-block; font-size: .625rem; font-weight: 600; letter-spacing: .1em;
    padding: .12rem .4rem; white-space: pre; border: 1px solid transparent;
}}
.sx-badge.crit {{ background: var(--stamp); color: #0C0C0C; }}
.sx-badge.high {{ color: var(--caution); border-color: var(--caution); }}
.sx-badge.med  {{ color: var(--fg); border-color: var(--rule-strong); }}
.sx-badge.low  {{ color: var(--fg-dim); border-color: var(--rule); }}

/* record table */
.sx-tablewrap {{ border: 1px solid var(--rule-strong); overflow-x: auto; }}
table.sx-table {{ width: 100%; border-collapse: collapse; font-size: .75rem; }}
table.sx-table thead th {{
    background: var(--bg-inset); color: var(--fg-dim); text-align: left; font-weight: 600;
    font-size: .625rem; letter-spacing: .14em; text-transform: uppercase;
    padding: .5rem .7rem; border-bottom: 1px solid var(--rule-strong); white-space: nowrap;
}}
table.sx-table tbody td {{
    padding: .42rem .7rem; border-bottom: 1px solid var(--rule); color: var(--fg);
    vertical-align: top;
}}
table.sx-table tbody tr:last-child td {{ border-bottom: none; }}
table.sx-table tbody tr:hover td {{ background: var(--bg-inset); }}
table.sx-table td.mono {{ font-feature-settings: "tnum"; color: var(--fg); white-space: nowrap; }}
table.sx-table td.num  {{ text-align: right; font-feature-settings: "tnum"; }}
table.sx-table td.dim  {{ color: var(--fg-dim); }}
table.sx-table tr[data-sev="critical"] td:first-child {{ box-shadow: inset 3px 0 0 var(--stamp); }}
table.sx-table tr[data-sev="high"]     td:first-child {{ box-shadow: inset 3px 0 0 var(--caution); }}

/* sidebar wordmark / operator */
.sx-wordmark {{ font-size: 1rem; font-weight: 700; letter-spacing: .22em; color: var(--fg); }}
.sx-wordmark::before {{ content: "\\25AE "; color: var(--stamp); }}
.sx-wordmark small {{ display: block; font-size: .55rem; letter-spacing: .22em; color: var(--fg-faint); margin-top: .1rem; }}
.sx-operator {{ font-size: .65rem; letter-spacing: .12em; text-transform: uppercase; color: var(--fg-dim);
                border-top: 1px solid var(--rule); padding-top: .7rem; margin-top: .5rem; }}
.sx-operator b {{ color: var(--caution); }}
.sx-navlabel {{ font-size: .6rem; letter-spacing: .18em; text-transform: uppercase; color: var(--fg-faint); margin: 1.2rem 0 .3rem; }}

/* field grid (incident dossier body) */
.sx-fields {{ display: grid; grid-template-columns: 8.5rem 1fr; gap: .1rem 1rem; margin: .4rem 0; }}
.sx-fields dt {{ font-size: .625rem; letter-spacing: .14em; text-transform: uppercase; color: var(--fg-dim); padding-top: .15rem; }}
.sx-fields dd {{ margin: 0; font-size: .78rem; color: var(--fg); }}
.sx-fields dd.mono {{ font-feature-settings: "tnum"; }}

/* empty state */
.sx-empty {{
    border: 1px dashed var(--rule-strong); background: var(--bg-raised);
    padding: 2.4rem 1rem; text-align: center;
}}
.sx-empty .head {{ font-size: .8rem; letter-spacing: .18em; text-transform: uppercase; color: var(--fg-dim); }}
.sx-empty .sub {{ font-size: .68rem; letter-spacing: .1em; text-transform: uppercase; color: var(--fg-faint); margin-top: .4rem; }}
.sx-empty .head::before {{ content: "// "; color: var(--stamp); }}
"""


def inject_css() -> None:
    """Emit the single consolidated stylesheet. Call once after set_page_config."""
    st.markdown(f"<style>{_CSS}</style>", unsafe_allow_html=True)


# --------------------------------------------------------------------------- #
# render helpers
# --------------------------------------------------------------------------- #
def _esc(v) -> str:
    return html.escape("" if v is None else str(v))


def banner() -> None:
    st.markdown(
        '<div class="sx-banner">Sentrexa &nbsp;//&nbsp; Security Operations Center '
        '&nbsp;//&nbsp; Simulated Environment &mdash; <b>UNCLASSIFIED // TRAINING</b></div>',
        unsafe_allow_html=True,
    )


def identity(posture: str) -> None:
    key = posture.lower()
    st.markdown(
        f'<div class="sx-ident"><span class="tick">&#9646;</span>'
        f'<h1>Sentrexa SOC</h1>'
        f'<span class="posture sx-posture-{key}">POSTURE&nbsp;&nbsp;{_esc(posture.upper())}</span>'
        f'</div>',
        unsafe_allow_html=True,
    )


def subline(text: str) -> None:
    st.markdown(f'<div class="sx-subline"><span class="live">{_esc(text)}</span></div>',
                unsafe_allow_html=True)


def ledger(cells: list[tuple[str, str, str, str]]) -> None:
    """cells: list of (label, value, note, kind) where kind in {'', 'accent', 'warn'}."""
    parts = [f'<div class="sx-ledger" style="--cols:{len(cells)}">']
    for label, value, note, kind in cells:
        parts.append(
            f'<div class="sx-cell {kind}">'
            f'<div class="lbl">{_esc(label)}</div>'
            f'<div class="val">{_esc(value)}</div>'
            f'<div class="note">{_esc(note)}</div></div>'
        )
    parts.append("</div>")
    st.markdown("".join(parts), unsafe_allow_html=True)


def section(name: str, meta: str = "") -> None:
    st.markdown(
        f'<div class="sx-sec"><span class="name">{_esc(name)}</span>'
        f'<span class="meta">{_esc(meta)}</span></div>',
        unsafe_allow_html=True,
    )


def severity_badge(severity: str) -> str:
    mod, token = SEVERITY_TOKENS.get(str(severity).lower(), ("med", str(severity)[:4].upper()))
    return f'<span class="sx-badge {mod}">{token}</span>'


def record_table(
    rows: list[dict],
    columns: list[tuple[str, str, str]],
    *,
    severity_key: str | None = None,
) -> None:
    """columns: list of (key, header, cls) where cls in {'', 'mono', 'num', 'dim', 'sev'}."""
    head = "".join(f"<th>{_esc(h)}</th>" for _, h, _ in columns)
    body = []
    for row in rows:
        sev = str(row.get(severity_key, "")).lower() if severity_key else ""
        attr = f' data-sev="{sev}"' if sev in ("critical", "high") else ""
        tds = []
        for key, _h, cls in columns:
            val = row.get(key)
            if cls == "sev":
                tds.append(f"<td>{severity_badge(val)}</td>")
            else:
                tds.append(f'<td class="{cls}">{_esc(val)}</td>')
        body.append(f"<tr{attr}>{''.join(tds)}</tr>")
    st.markdown(
        f'<div class="sx-tablewrap"><table class="sx-table"><thead><tr>{head}</tr>'
        f'</thead><tbody>{"".join(body)}</tbody></table></div>',
        unsafe_allow_html=True,
    )


def fields(pairs: list[tuple[str, str, bool]]) -> None:
    """pairs: list of (label, value, is_mono)."""
    inner = "".join(
        f"<dt>{_esc(k)}</dt><dd class=\"{'mono' if mono else ''}\">{_esc(v)}</dd>"
        for k, v, mono in pairs
    )
    st.markdown(f'<dl class="sx-fields">{inner}</dl>', unsafe_allow_html=True)


def empty_state(head: str, sub: str = "") -> None:
    st.markdown(
        f'<div class="sx-empty"><div class="head">{_esc(head)}</div>'
        f'<div class="sub">{_esc(sub)}</div></div>',
        unsafe_allow_html=True,
    )


# --------------------------------------------------------------------------- #
# Plotly theming
# --------------------------------------------------------------------------- #
def style_fig(fig, *, height: int = 300, horizontal: bool = False, legend: bool = True):
    axis = dict(
        gridcolor=PALETTE["rule"], zerolinecolor=PALETTE["rule_strong"],
        linecolor=PALETTE["rule_strong"], tickcolor=PALETTE["rule_strong"],
        title=None, showgrid=True, gridwidth=1, ticks="outside", ticklen=3,
    )
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor=PALETTE["bg"],
        plot_bgcolor=PALETTE["bg"],
        font=dict(family="IBM Plex Mono, monospace", color=PALETTE["fg_dim"], size=11),
        colorway=CHART_SEQUENCE,
        height=height,
        margin=dict(l=170 if horizontal else 44, r=16,
                    t=58 if horizontal else 40, b=34),
        title=dict(font=dict(size=11, color=PALETTE["fg"], family="IBM Plex Mono"),
                   x=0, xanchor="left", y=0.97, yanchor="top"),
        showlegend=legend,
        legend=dict(bgcolor="rgba(0,0,0,0)", borderwidth=0, font=dict(size=9),
                    orientation="h", yanchor="bottom", y=1.02, x=0),
        xaxis=axis, yaxis=axis,
        bargap=0.35,
    )
    for tr in fig.data:
        if tr.type == "bar":
            tr.marker.line.width = 0
        if tr.type == "scatter":
            tr.line.width = 1.5
    return fig


def now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
