"""
Role-Based Access Control (RBAC)
=================================
Five-tier role hierarchy aligned to fashion retail org structures.

Role hierarchy (ascending privilege)
-------------------------------------
  MA (1)           Merchandise Assistant   — operational monitoring only
  AM (2)           Assistant Merchandiser  — trading analysis + AI insights
  Merchandiser (3) Merchandiser            — full analysis + action centre
  Director (4)     Trading Director        — executive views + security centre
  Admin (5)        Platform Admin          — user management + all settings

Principle of least privilege
----------------------------
Every role inherits only what it strictly needs.
Roles do NOT inherit all permissions of lower tiers automatically —
each permission is explicitly mapped so the matrix is auditable.
"""

import functools
import logging
from flask import jsonify

log = logging.getLogger(__name__)

# ── Role levels ────────────────────────────────────────────────────────────────
ROLE_LEVELS: dict[str, int] = {
    "MA":          1,
    "AM":          2,
    "Merchandiser":3,
    "Director":    4,
    "Admin":       5,
}

VALID_ROLES = set(ROLE_LEVELS.keys())

# ── Permission → minimum required role ────────────────────────────────────────
# Every API action maps to the minimum role that can perform it.
# Anything not listed here is implicitly DENIED.
PERMISSIONS: dict[str, str] = {
    # Dashboard & uploads
    "view_dashboard":         "MA",
    "upload_file":            "MA",
    "view_analysis":          "MA",
    "view_own_uploads":       "MA",

    # AI features
    "ai_chat":                "MA",
    "view_quick_insights":    "MA",
    "view_ai_insights":       "AM",

    # Reports
    "view_report":            "AM",
    "generate_report":        "AM",
    "export_report_pdf":      "AM",
    "export_report_pptx":     "AM",

    # Action Centre
    "view_action_centre":     "Merchandiser",
    "action_centre_api":      "Merchandiser",

    # Security & admin
    "view_security_centre":   "Director",
    "view_audit_logs":        "Director",
    "view_all_users":         "Director",
    "change_retention_policy":"Director",
    "toggle_private_mode":    "Director",

    # User management
    "manage_users":           "Admin",
    "change_user_role":       "Admin",
    "suspend_user":           "Admin",
    "delete_uploads_any":     "Admin",

    # Self-service
    "change_own_profile":     "MA",    # All roles can update their own name/password
}


def level(role: str) -> int:
    """Return numeric privilege level for a role string."""
    return ROLE_LEVELS.get(role, 0)


def has_permission(user_role: str, action: str) -> bool:
    """
    Return True if user_role satisfies the minimum level required for action.
    Unknown actions return False (deny-by-default).
    """
    required_role = PERMISSIONS.get(action)
    if not required_role:
        return False
    return level(user_role) >= level(required_role)


def require_permission(action: str):
    """
    Route decorator — enforces RBAC before the handler runs.

    Usage::

        @app.route("/action-centre")
        @require_auth
        @require_permission("view_action_centre")
        def action_centre(user): ...

    The decorator expects `user` to be available as a keyword argument
    (supplied by the @require_auth decorator that must run first).
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            user = kwargs.get("user")
            if not user:
                return jsonify({"error": "Authentication required"}), 401

            role = user.get("role", "MA")
            if not has_permission(role, action):
                log.warning(
                    f"[RBAC] DENIED  user={user.get('id')}  "
                    f"role={role}  action={action}"
                )
                return jsonify({
                    "error":    "Access denied — insufficient permissions",
                    "required": PERMISSIONS.get(action, "unknown"),
                    "current":  role,
                    "action":   action,
                }), 403

            return f(*args, **kwargs)
        return wrapper
    return decorator


def require_company_ownership(user: dict, resource_company_id: str) -> bool:
    """
    Verify that the user's company_id matches the resource's company_id.
    Admins can access any company's resources.
    """
    if user.get("role") == "Admin":
        return True
    user_company = str(user.get("company_id", ""))
    resource_company = str(resource_company_id or "")
    if not user_company or not resource_company:
        return False
    return user_company == resource_company
