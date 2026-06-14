"""
HTTP Security Headers
=====================
Applies a comprehensive set of security headers to every response.

Headers applied
---------------
Content-Security-Policy     — restricts resource origins (XSS mitigation)
Strict-Transport-Security   — enforces HTTPS for 1 year (HSTS)
X-Content-Type-Options      — prevents MIME sniffing
X-Frame-Options             — clickjacking protection
X-XSS-Protection            — legacy browser XSS filter
Referrer-Policy             — limits referrer leakage
Permissions-Policy          — disables dangerous browser APIs
Cache-Control               — prevents sensitive API responses from being cached
Cross-Origin-Opener-Policy  — isolates browsing contexts
Cross-Origin-Resource-Policy— controls cross-origin reads

CSRF Protection
---------------
POST/PUT/PATCH/DELETE requests to /api/* require a CSRF token.
The token is issued as a cookie (readable by JS) and must be echoed
in the X-CSRF-Token request header.
Pattern: Double-Submit Cookie (OWASP recommended for SPAs).
"""

import os
import secrets
import logging
from flask import Flask, request, redirect, abort, session

log = logging.getLogger(__name__)

# ── Content Security Policy ────────────────────────────────────────────────────
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://js.stripe.com https://fonts.googleapis.com; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' data: https://fonts.gstatic.com; "
    "img-src 'self' data: blob:; "
    "connect-src 'self' https://api.stripe.com; "
    "frame-src https://js.stripe.com; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "upgrade-insecure-requests;"
)

# Endpoints exempt from CSRF (Stripe webhooks use signature-based auth)
_CSRF_EXEMPT = frozenset({
    "/webhooks/stripe",
    "/health",
})

# Methods that require CSRF token
_CSRF_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def apply_security_headers(app: Flask) -> None:
    """
    Register before/after request hooks on the Flask app.
    Call once at startup:  apply_security_headers(app)
    """

    # ── HTTPS enforcement ──────────────────────────────────────────────────────
    @app.before_request
    def enforce_https():
        """Redirect plain HTTP to HTTPS in production."""
        if os.environ.get("FLASK_ENV") != "production":
            return
        proto = request.headers.get("X-Forwarded-Proto", "")
        if proto == "http":
            url = request.url.replace("http://", "https://", 1)
            return redirect(url, code=301)

    # ── CSRF protection ────────────────────────────────────────────────────────
    @app.before_request
    def csrf_protect():
        """
        Double-Submit Cookie CSRF protection for state-changing API calls.
        Skips: GET/HEAD/OPTIONS, exempt paths, Stripe webhook.
        """
        if request.method not in _CSRF_METHODS:
            return
        if request.path in _CSRF_EXEMPT:
            return
        if not request.path.startswith("/api/"):
            return

        # Ensure the CSRF cookie exists (issue on first visit)
        token_in_session = session.get("csrf_token")
        if not token_in_session:
            # If no session yet (e.g. login endpoint), skip check
            if request.path in ("/auth/login", "/auth/signup", "/auth/verify-email",
                                 "/auth/forgot-password", "/auth/reset-password"):
                return
            abort(403)

        token_in_header = request.headers.get("X-CSRF-Token", "")
        if not secrets.compare_digest(token_in_session, token_in_header):
            log.warning(
                f"[CSRF] Token mismatch for {request.method} {request.path} "
                f"from {request.remote_addr}"
            )
            abort(403)

    # ── Security response headers ──────────────────────────────────────────────
    @app.after_request
    def add_security_headers(response):
        h = response.headers

        h["Content-Security-Policy"]       = _CSP
        h["X-Content-Type-Options"]        = "nosniff"
        h["X-Frame-Options"]               = "SAMEORIGIN"
        h["X-XSS-Protection"]              = "1; mode=block"
        h["Referrer-Policy"]               = "strict-origin-when-cross-origin"
        h["Permissions-Policy"]            = (
            "geolocation=(), microphone=(), camera=(), "
            "payment=(), usb=(), magnetometer=()"
        )
        h["Cross-Origin-Opener-Policy"]    = "same-origin"
        h["Cross-Origin-Resource-Policy"]  = "same-origin"

        # HSTS — only over HTTPS
        is_https = (
            request.is_secure
            or request.headers.get("X-Forwarded-Proto") == "https"
        )
        if is_https:
            h["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # Prevent caching of API responses
        if request.path.startswith("/api/"):
            h["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            h["Pragma"]        = "no-cache"
            h["Expires"]       = "0"

        # Remove server fingerprinting headers
        h.remove("Server")
        h.remove("X-Powered-By")

        return response


def generate_csrf_token() -> str:
    """
    Generate a cryptographically secure CSRF token and store it in session.
    Call this during login and return it to the client.
    """
    token = secrets.token_hex(32)
    session["csrf_token"] = token
    return token


def get_csrf_token() -> str:
    """Return current session CSRF token, generating one if absent."""
    token = session.get("csrf_token")
    if not token:
        token = generate_csrf_token()
    return token
