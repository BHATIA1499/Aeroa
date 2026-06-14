"""
Rate Limiting
=============
Per-endpoint rate limits with IP + user-ID keying to prevent:
  - Credential brute-force on auth endpoints
  - AI resource exhaustion on chat/report endpoints
  - File upload flooding
  - Scraping of analysis data

Storage: in-memory (single-process).  For multi-process Railway deployments,
swap storage_uri to a Redis URL: "redis://localhost:6379/0"
"""

import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ── Limiter instance (attached to app in create_limiter()) ────────────────────
_limiter: Limiter | None = None


def create_limiter(app) -> Limiter:
    """Initialise Flask-Limiter and attach it to the Flask app."""
    global _limiter

    redis_url = os.environ.get("REDIS_URL", "")
    storage   = redis_url if redis_url else "memory://"

    _limiter = Limiter(
        app=app,
        key_func=_keyed_by_ip_and_user,
        default_limits=["300 per minute", "3000 per hour"],
        storage_uri=storage,
        headers_enabled=True,          # Expose X-RateLimit-* headers
        swallow_errors=True,           # Never crash the app on limiter error
    )
    return _limiter


def get_limiter() -> Limiter:
    if _limiter is None:
        raise RuntimeError("Rate limiter not initialised — call create_limiter(app) first.")
    return _limiter


def _keyed_by_ip_and_user() -> str:
    """
    Key by IP + user session when available; fall back to IP only.
    Prevents shared-IP environments (offices, VPNs) from being
    rate-limited as a single entity for auth endpoints.
    """
    from flask import session, request
    uid = session.get("user_id", "")
    ip  = get_remote_address()
    return f"{ip}:{uid}" if uid else ip


# ── Per-endpoint limit decorators ─────────────────────────────────────────────
#
# Apply these AFTER @require_auth so the user is always identified.
# Usage:
#   @app.route("/auth/login", methods=["POST"])
#   @AUTH_LIMIT
#   def login(): ...

def auth_limit():
    """Brute-force protection: 10 attempts per minute per IP."""
    return get_limiter().limit("10 per minute", key_func=get_remote_address)

def upload_limit():
    """Prevent upload flooding: 30 uploads per hour per user."""
    return get_limiter().limit("30 per hour")

def ai_chat_limit():
    """AI resource protection: 60 messages per minute per user."""
    return get_limiter().limit("60 per minute")

def report_limit():
    """Report generation: 10 per hour (Claude calls are expensive)."""
    return get_limiter().limit("10 per hour")

def export_limit():
    """Data exports: 20 per hour."""
    return get_limiter().limit("20 per hour")

def api_limit():
    """General API: 120 per minute."""
    return get_limiter().limit("120 per minute")
