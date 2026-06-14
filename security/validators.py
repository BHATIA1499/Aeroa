"""
Input Validation & Sanitisation
================================
Centralised validation for all user-supplied input.

Defends against
---------------
- SQL injection      (parameterised queries via Supabase client handle most of
                      this, but we add an additional pattern-based check)
- XSS               (HTML entity encoding on all string output)
- Path traversal    (filename sanitisation)
- Unicode attacks   (normalisation before comparison)
- Excessively long  (hard length caps on every field)
- Type confusion    (strict type checking before processing)

Usage
-----
    from security.validators import sanitise, validate_email, safe_filename

    email    = sanitise(body.get("email"), kind="email")
    filename = safe_filename(uploaded_file.filename)
"""

import re
import unicodedata
import logging
from html import escape as html_escape

log = logging.getLogger(__name__)

# ── Length limits ──────────────────────────────────────────────────────────────
_MAX_LENGTHS: dict[str, int] = {
    "email":    254,
    "password": 1024,
    "name":     200,
    "filename": 255,
    "message":  10_000,
    "role":     50,
    "uuid":     36,
    "default":  2_000,
}

# ── SQL injection patterns ─────────────────────────────────────────────────────
# Supabase uses parameterised queries for all table operations, so raw SQL
# injection via the ORM is already mitigated.  These checks guard any
# string values that might flow into query parameters or prompt construction.
_SQL_PATTERNS = re.compile(
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|TRUNCATE|GRANT|REVOKE)\b"
    r"|--\s|;\s*--|/\*.*?\*/|\bOR\b\s+\d+\s*=\s*\d+|\bAND\b\s+\d+\s*=\s*\d+)",
    re.IGNORECASE | re.DOTALL,
)

# ── XSS patterns (belt-and-suspenders, after HTML escaping) ───────────────────
_XSS_PATTERNS = re.compile(
    r"(<script|javascript:|vbscript:|data:text/html|on\w+\s*=)",
    re.IGNORECASE,
)

# Email regex (RFC 5322 simplified, avoids catastrophic backtracking)
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,253}\.[a-zA-Z]{2,}$"
)

# UUID v4
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Safe filename characters
_UNSAFE_FILENAME_RE = re.compile(r'[^\w\s\-_\.]')


# ── Core sanitiser ────────────────────────────────────────────────────────────

def sanitise(value, kind: str = "default") -> str:
    """
    Sanitise a string value for safe use throughout the application.

    Steps
    -----
    1. Type coerce to str
    2. Unicode NFKC normalise (prevents homograph attacks)
    3. Strip leading/trailing whitespace
    4. Truncate to max length for kind
    5. HTML-escape special characters

    Parameters
    ----------
    value : Any — will be converted to str
    kind  : One of "email", "name", "message", "filename", "role", "uuid", "default"

    Returns
    -------
    Sanitised string (never raises).
    """
    if value is None:
        return ""
    s = str(value)
    # Normalise unicode (NFKC folds ＜ → < etc.)
    s = unicodedata.normalize("NFKC", s)
    s = s.strip()
    max_len = _MAX_LENGTHS.get(kind, _MAX_LENGTHS["default"])
    s = s[:max_len]
    # HTML-escape (& → &amp;  < → &lt; etc.)
    s = html_escape(s, quote=True)
    return s


def sanitise_raw(value, kind: str = "default") -> str:
    """
    Like sanitise() but does NOT HTML-escape — for values used
    programmatically (e.g. sent to the AI, stored as JSON).
    """
    if value is None:
        return ""
    s = str(value)
    s = unicodedata.normalize("NFKC", s)
    s = s.strip()
    max_len = _MAX_LENGTHS.get(kind, _MAX_LENGTHS["default"])
    return s[:max_len]


# ── Type validators ────────────────────────────────────────────────────────────

def validate_email(email: str) -> bool:
    """Return True if email passes format validation."""
    return bool(_EMAIL_RE.match(sanitise_raw(email, "email")))


def validate_uuid(value: str) -> bool:
    """Return True if value is a well-formed UUID v4."""
    return bool(_UUID_RE.match(str(value).lower()))


def validate_role(role: str) -> bool:
    """Return True if role is one of the five valid role strings."""
    from security.rbac import VALID_ROLES
    return sanitise_raw(role, "role") in VALID_ROLES


def validate_password(password: str) -> tuple[bool, str]:
    """
    Password strength validation.
    Returns (ok, error_message).
    """
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters."
    if len(password) > 1024:
        return False, "Password is too long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number."
    return True, ""


# ── Filename sanitisation ──────────────────────────────────────────────────────

def safe_filename(filename: str) -> str:
    """
    Sanitise a filename:
    - Remove path separators (prevent directory traversal)
    - Remove null bytes and control characters
    - Replace dangerous characters with underscores
    - Strip leading dots (hidden file trick)
    - Truncate to 255 chars
    """
    if not filename:
        return "upload"
    # Take only the basename (never the path)
    filename = filename.replace("\\", "/").split("/")[-1]
    # Remove null bytes and non-printable ASCII
    filename = re.sub(r"[\x00-\x1f\x7f]", "", filename)
    # Replace path-dangerous characters
    filename = re.sub(r'[/\\:*?"<>|]', "_", filename)
    # Strip leading dots
    filename = filename.lstrip(".")
    # Truncate
    filename = filename[:255]
    return filename or "upload"


# ── Injection detectors ────────────────────────────────────────────────────────

def has_sql_injection(value: str) -> bool:
    """
    Return True if value contains SQL injection patterns.
    Use as an additional check — do not rely on this alone.
    """
    return bool(_SQL_PATTERNS.search(str(value)))


def has_xss(value: str) -> bool:
    """Return True if value contains XSS patterns (after HTML-escaping)."""
    return bool(_XSS_PATTERNS.search(str(value)))


def check_and_sanitise(value, kind: str = "default") -> tuple[str, bool]:
    """
    Sanitise and check for injection in one call.
    Returns (sanitised_value, is_safe).
    is_safe=False means an injection attempt was detected.
    """
    raw   = sanitise_raw(value, kind)
    clean = sanitise(value, kind)
    safe  = not (has_sql_injection(raw) or has_xss(raw))
    if not safe:
        log.warning(f"[VALIDATORS] Potential injection detected in {kind} field: {raw[:80]!r}")
    return clean, safe
