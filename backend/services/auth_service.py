"""Login and session handling for SERC. Standard library only (no new dependencies).

* Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes, never in plain text.
* A session is a signed token kept in an HttpOnly cookie. It carries the user name, an expiry time and a short
  fingerprint of the password hash, so changing a password signs out every older session.
* Repeated wrong passwords lock that user name + IP address for a few minutes.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("serc.auth")

PBKDF2_ITERATIONS = 310_000
MIN_PASSWORD_LENGTH = 8
USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{3,64}$")
ROLES = {"admin", "analyst"}
GENERIC_LOGIN_ERROR = "Incorrect user name or password."


# ------------------------------------------------------------------ password hashing
def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(iterations, base64.b64encode(salt).decode(), base64.b64encode(digest).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt_b64, digest_b64 = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        salt, expected = base64.b64decode(salt_b64), base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


# Used to spend the same time on unknown user names as on real ones (avoids revealing which names exist).
_DUMMY_HASH = hash_password("serc-dummy-password-not-used")


def load_or_create_secret(configured: str, secret_file: Path) -> bytes:
    """Use SECRET_KEY from the environment if given, otherwise create one once and keep it in a private file,
    so users stay signed in across server restarts."""
    if configured and configured.strip():
        return configured.strip().encode("utf-8")
    secret_file = Path(secret_file)
    try:
        if secret_file.exists():
            value = secret_file.read_text(encoding="utf-8").strip()
            if len(value) >= 32:
                return value.encode("utf-8")
        secret_file.parent.mkdir(parents=True, exist_ok=True)
        value = secrets.token_urlsafe(48)
        secret_file.write_text(value, encoding="utf-8")
        try:
            secret_file.chmod(0o600)
        except OSError:
            pass  # Windows: chmod has little effect
        return value.encode("utf-8")
    except OSError as exc:
        logger.warning("Could not store the session secret (%s). Sessions will end when the server restarts.", exc)
        return secrets.token_urlsafe(48).encode("utf-8")


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class AuthService:
    def __init__(self, db_path: Path, secret: bytes, session_hours: float = 8,
                 max_failures: int = 5, lockout_seconds: int = 300):
        self.db_path = Path(db_path)
        self.secret = secret
        self.session_seconds = int(session_hours * 3600)
        self.max_failures = max_failures
        self.lockout_seconds = lockout_seconds
        self._ready = False
        self._failures: Dict[Tuple[str, str], Tuple[int, float]] = {}  # (user, ip) -> (count, locked_until)
        self._lock = threading.Lock()

    # ------------------------------------------------------------ storage
    @contextmanager
    def _conn(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            if not self._ready:
                conn.execute(
                    """CREATE TABLE IF NOT EXISTS users (
                           id INTEGER PRIMARY KEY AUTOINCREMENT,
                           username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                           password_hash TEXT NOT NULL,
                           role TEXT NOT NULL DEFAULT 'analyst',
                           active INTEGER NOT NULL DEFAULT 1,
                           created_at TEXT NOT NULL
                       )""")
                self._ready = True
            yield conn
            conn.commit()
        finally:
            conn.close()

    def user_count(self) -> int:
        with self._conn() as c:
            return int(c.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    def _row(self, username: str) -> Optional[sqlite3.Row]:
        with self._conn() as c:
            return c.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()

    @staticmethod
    def check_password_rules(password: str) -> None:
        if len(password or "") < MIN_PASSWORD_LENGTH:
            raise ValueError(f"The password must be at least {MIN_PASSWORD_LENGTH} characters long.")

    def create_user(self, username: str, password: str, role: str = "analyst") -> Dict[str, Any]:
        username = (username or "").strip()
        if not USERNAME_RE.match(username):
            raise ValueError("The user name must be 3 to 64 characters: letters, digits and . _ @ - only.")
        if role not in ROLES:
            raise ValueError(f"The role must be one of {sorted(ROLES)}.")
        self.check_password_rules(password)
        try:
            with self._conn() as c:
                c.execute("INSERT INTO users (username, password_hash, role, active, created_at) VALUES (?,?,?,1,?)",
                          (username, hash_password(password), role, time.strftime("%Y-%m-%d %H:%M:%S")))
        except sqlite3.IntegrityError:
            raise ValueError(f"The user '{username}' already exists.")
        return {"username": username, "role": role}

    def set_password(self, username: str, new_password: str) -> None:
        self.check_password_rules(new_password)
        with self._conn() as c:
            cur = c.execute("UPDATE users SET password_hash=? WHERE username=?", (hash_password(new_password), username))
            if cur.rowcount == 0:
                raise ValueError(f"No user named '{username}'.")

    def ensure_default_admin(self, username: str, password: str = "") -> Optional[str]:
        """Create the first admin when the user table is empty. Returns a generated password (to be shown once
        in the server console) or None when nothing was generated."""
        if self.user_count() > 0:
            return None
        generated = None
        if not password or len(password) < MIN_PASSWORD_LENGTH:
            if password:
                logger.warning("ADMIN_PASSWORD is shorter than %d characters, so a random one was generated instead.", MIN_PASSWORD_LENGTH)
            password = generated = secrets.token_urlsafe(12)
        self.create_user(username or "admin", password, role="admin")
        return generated

    # ------------------------------------------------------------ login
    def _throttle_key(self, username: str, ip: str) -> Tuple[str, str]:
        return (username.strip().lower(), ip or "")

    def _locked_for(self, key: Tuple[str, str]) -> int:
        with self._lock:
            count, until = self._failures.get(key, (0, 0.0))
            remaining = int(until - time.time())
            if remaining > 0:
                return remaining
            if until and remaining <= 0:
                self._failures.pop(key, None)  # lock expired
        return 0

    def _record_failure(self, key: Tuple[str, str]) -> None:
        with self._lock:
            count, _ = self._failures.get(key, (0, 0.0))
            count += 1
            until = time.time() + self.lockout_seconds if count >= self.max_failures else 0.0
            self._failures[key] = (count, until)

    def authenticate(self, username: str, password: str, ip: str = "") -> Tuple[Optional[Dict[str, Any]], str, int]:
        """Returns (user or None, error message, seconds to wait)."""
        key = self._throttle_key(username or "", ip)
        wait = self._locked_for(key)
        if wait:
            return None, f"Too many failed attempts. Try again in {max(1, round(wait / 60))} minute(s).", wait
        row = self._row((username or "").strip()) if USERNAME_RE.match((username or "").strip()) else None
        ok = verify_password(password or "", row["password_hash"] if row else _DUMMY_HASH)
        if row and ok:
            with self._lock:
                self._failures.pop(key, None)
            return {"username": row["username"], "role": row["role"]}, "", 0
        self._record_failure(key)
        return None, GENERIC_LOGIN_ERROR, 0

    def change_password(self, username: str, current: str, new: str) -> None:
        row = self._row(username)
        if not row or not verify_password(current or "", row["password_hash"]):
            raise ValueError("The current password is not correct.")
        if current == new:
            raise ValueError("The new password must be different from the current one.")
        self.set_password(username, new)

    # ------------------------------------------------------------ sessions
    @staticmethod
    def _fingerprint(password_hash: str) -> str:
        return hashlib.sha256(password_hash.encode()).hexdigest()[:10]

    def _sign(self, payload: str) -> str:
        return _b64u(hmac.new(self.secret, payload.encode("utf-8"), hashlib.sha256).digest())

    def issue_token(self, username: str) -> str:
        row = self._row(username)
        if not row:
            raise ValueError("Unknown user.")
        payload = f"{row['username']}|{int(time.time()) + self.session_seconds}|{self._fingerprint(row['password_hash'])}"
        return f"{_b64u(payload.encode('utf-8'))}.{self._sign(payload)}"

    def user_from_token(self, token: Optional[str]) -> Optional[Dict[str, Any]]:
        if not token or "." not in token:
            return None
        try:
            body, sig = token.split(".", 1)
            payload = _unb64u(body).decode("utf-8")
            if not hmac.compare_digest(sig, self._sign(payload)):
                return None
            username, expires, fp = payload.split("|")
            if int(expires) < time.time():
                return None
            row = self._row(username)
            if not row or not hmac.compare_digest(fp, self._fingerprint(row["password_hash"])):
                return None
            return {"username": row["username"], "role": row["role"]}
        except (ValueError, TypeError, UnicodeDecodeError):
            return None
