"""Credential gate for the dashboard (streamlit-authenticator).

A single analyst account, its bcrypt hash supplied via
``DASHBOARD_AUTH_PASSWORD_HASH`` (env locally, Streamlit Cloud / Actions secret
in deployment). ``require_login`` renders the login form and stops the script
until the visitor authenticates.
"""

from __future__ import annotations

import streamlit as st
import streamlit_authenticator as stauth

from config.settings import settings

_auth_cfg = settings.dashboard_auth


def _authenticator() -> stauth.Authenticate:
    return stauth.Authenticate(
        _auth_cfg.credentials(),
        _auth_cfg.cookie_name,
        _auth_cfg.cookie_key,
        _auth_cfg.cookie_expiry_days,
        auto_hash=False,  # the password is already a bcrypt hash
    )


def require_login() -> str:
    """Block until logged in. Returns the display name. Calls st.stop() otherwise."""
    if not _auth_cfg.configured:
        st.error(
            "Dashboard auth is not configured. Set DASHBOARD_AUTH_PASSWORD_HASH "
            "(see `python -m dashboard.hash_password`)."
        )
        st.stop()

    authenticator = _authenticator()

    frame = st.container()          # reserve the slot above the login form
    authenticator.login(location="main")
    status = st.session_state.get("authentication_status")

    if status is True:
        # default key ("Logout"); a custom key of "logout" collides with the
        # session_state flag streamlit-authenticator sets internally.
        authenticator.logout(button_name="Sign out", location="sidebar")
        return st.session_state.get("name", "analyst")

    with frame:                     # only drawn while unauthenticated
        st.markdown(
            '<div class="sx-banner">Sentrexa &nbsp;//&nbsp; Security Operations Center '
            '&nbsp;//&nbsp; <b>RESTRICTED — ANALYST ACCESS</b></div>'
            '<div class="sx-ident"><span class="tick">&#9646;</span>'
            '<h1>Sentrexa SOC</h1></div>'
            '<div class="sx-subline">authenticate to open the operations terminal</div>',
            unsafe_allow_html=True,
        )
        if status is False:
            st.error("Credential rejected — incorrect username or password.")
    st.stop()
