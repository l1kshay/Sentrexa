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
    authenticator.login(location="main")

    status = st.session_state.get("authentication_status")
    if status is False:
        st.error("Incorrect username or password.")
        st.stop()
    if status is None:
        st.info("Please log in to view the Sentrexa SOC dashboard.")
        st.stop()

    authenticator.logout(location="sidebar", key="logout")
    return st.session_state.get("name", "analyst")
