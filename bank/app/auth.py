"""
Session-based authentication and user management for the mock bank.
"""

import hmac
import time
import uuid
from typing import Optional, Dict, Any
from fastapi import Request
from bank.app.seed import BankUser, get_default_seed_users


class BankAuthManager:
    """
    Manages user sessions and authentication with timing-safe comparisons and session expiry.
    """

    SESSION_MAX_AGE_SECONDS = 86400  # 24 hours

    def __init__(self) -> None:
        self.users: Dict[str, BankUser] = get_default_seed_users()
        self.sessions: Dict[str, Dict[str, Any]] = {}  # token -> {"username": str, "created_at": float}

    def authenticate(self, username: str, password: str) -> Optional[BankUser]:
        user = self.users.get(username)
        if user and hmac.compare_digest(user.password.encode("utf-8"), password.encode("utf-8")):
            return user
        return None

    def create_session(self, username: str) -> str:
        token = f"sess-{uuid.uuid4().hex}"
        self.sessions[token] = {
            "username": username,
            "created_at": time.time()
        }
        return token

    def get_current_user(self, request: Request) -> Optional[BankUser]:
        token = request.cookies.get("session_token")
        if not token or token not in self.sessions:
            return None
        sess = self.sessions[token]
        # Check session expiration
        if time.time() - sess.get("created_at", 0) > self.SESSION_MAX_AGE_SECONDS:
            del self.sessions[token]
            return None
        username = sess["username"]
        return self.users.get(username)

    def revoke_session(self, request: Request) -> None:
        token = request.cookies.get("session_token")
        if token and token in self.sessions:
            del self.sessions[token]

    def reset_users(self) -> None:
        self.users = get_default_seed_users()
        self.sessions.clear()

