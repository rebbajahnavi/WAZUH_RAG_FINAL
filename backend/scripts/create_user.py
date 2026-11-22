"""Add a user or reset a password without starting the server.

    python backend/scripts/create_user.py alice                 (asks for the password)
    python backend/scripts/create_user.py alice --role admin
    python backend/scripts/create_user.py alice --reset         (set a new password for an existing user)
"""
import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.config import settings  # noqa: E402
from backend.services.auth_service import AuthService  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Create a SERC user or reset a password.")
    ap.add_argument("username")
    ap.add_argument("--role", choices=["analyst", "admin"], default="analyst")
    ap.add_argument("--reset", action="store_true", help="set a new password for an existing user")
    args = ap.parse_args()

    svc = AuthService(settings.auth_db_file, secret=b"unused-here")
    password = getpass.getpass("Password: ")
    if password != getpass.getpass("Repeat password: "):
        print("The passwords do not match.")
        return 1
    try:
        if args.reset:
            svc.set_password(args.username, password)
            print(f"Password changed for '{args.username}'. Their older sessions are now signed out.")
        else:
            svc.create_user(args.username, password, args.role)
            print(f"User '{args.username}' created ({args.role}).")
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
