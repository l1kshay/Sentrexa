"""Generate a bcrypt hash for the dashboard login password.

    python -m dashboard.hash_password 'my secret password'

Copy the printed hash into DASHBOARD_AUTH_PASSWORD_HASH (in .env locally, or the
Streamlit Cloud / GitHub Actions secret). The plaintext is never stored.
"""

from __future__ import annotations

import getpass
import sys

import bcrypt


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    password = argv[0] if argv else getpass.getpass("Password: ")
    if not password:
        print("empty password", file=sys.stderr)
        return 1
    print(bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
